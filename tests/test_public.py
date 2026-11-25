from datetime import datetime

from engine.alerts.dedup import absorb, dedup_batch, fingerprint

NOW = datetime(2026, 11, 19, 9, 0, 0)
POLICY = {"window_seconds": 300, "escalate_after": 3, "escalate_severity": "high"}


def new_state():
    return {"entries": {}, "sequence": 0}


def make_alert(
    entity="api-1",
    rule="privesc",
    severity="high",
    *,
    alert_id=None,
    at=None,
    repeat=1,
):
    return {
        "alert_id": alert_id or f"{entity}-{rule}-{severity}",
        "entity": entity,
        "rule": rule,
        "severity": severity,
        "timestamp": at or NOW,
        "repeat": repeat,
    }


def test_single_alert_enters_state():
    state = new_state()

    entry = absorb(state, make_alert(entity="api-1", severity="critical"), NOW, POLICY)

    assert len(state["entries"]) == 1
    assert entry["count"] == 1
    assert entry["first_seen"] == NOW
    assert entry["escalated"] is True


def test_same_fingerprint_merges_into_one_main_alert():
    state = new_state()

    first = absorb(state, make_alert(), NOW, POLICY)
    second = absorb(state, make_alert(), NOW, POLICY)

    assert len(state["entries"]) == 1
    assert second["alert_id"] == first["alert_id"]
    assert second["count"] == 2


def test_repeat_counts_accumulate():
    state = new_state()

    absorb(state, make_alert(repeat=2), NOW, POLICY)
    entry = absorb(state, make_alert(repeat=3), NOW, POLICY)

    assert entry["count"] == 5


def test_different_fingerprints_stay_apart():
    state = new_state()
    high = make_alert(entity="api-1", severity="high")
    critical = make_alert(entity="api-2", severity="critical")

    absorb(state, high, NOW, POLICY)
    absorb(state, critical, NOW, POLICY)

    assert fingerprint(high) != fingerprint(critical)
    assert len(state["entries"]) == 2


def test_batches_are_independent():
    first = make_alert(alert_id="a-1")
    second = make_alert(alert_id="a-2")

    result = dedup_batch([[first], [second]], NOW, POLICY)
    key = fingerprint(first)

    assert result["batches"][0]["mains"][key] == "a-1"
    assert result["batches"][1]["mains"][key] == "a-2"
    assert result["batches"][1]["counts"][key] == 1