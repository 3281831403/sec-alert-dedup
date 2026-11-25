from datetime import datetime, timedelta

import pytest

from engine.alerts import dedup

NOW = datetime(2026, 11, 19, 9, 0, 0)
POLICY = {"window_seconds": 60, "escalate_after": 3, "escalate_severity": "high"}


def state():
    return {"entries": {}, "sequence": 0}


def alert(entity="api-1", rule="privesc", severity="high", *, alert_id=None, at=None, repeat=1):
    data = {
        "alert_id": alert_id or f"{entity}-{rule}-{severity}",
        "entity": entity,
        "rule": rule,
        "severity": severity,
        "repeat": repeat,
    }
    if at is not None:
        data["timestamp"] = at
    return data


def test_fingerprint_includes_entity_rule_and_severity():
    left = alert(entity="api-1", severity="high")
    right = alert(entity="api-1", severity="critical")
    other_rule = alert(entity="api-1", rule="xss", severity="high")

    assert dedup.fingerprint(left).count("|") == 2
    assert len({dedup.fingerprint(left), dedup.fingerprint(right), dedup.fingerprint(other_rule)}) == 3


def test_window_of_counts_from_epoch():
    at = NOW + timedelta(seconds=30)
    span = POLICY["window_seconds"]
    assert dedup.window_of(alert(at=at), NOW, POLICY) == int(
        (at - datetime(1970, 1, 1)).total_seconds() // span
    )


def test_severity_rank_is_low_to_high():
    ranks = [dedup.severity_rank(s) for s in ("low", "medium", "high", "critical")]
    assert ranks == sorted(ranks) and len(set(ranks)) == 4


def test_repeat_at_threshold_escalates_and_retriggers_notification():
    entry = dedup.absorb(state_object := state(), alert(repeat=2, severity="low"), NOW, POLICY)
    assert entry["escalated"] is False

    entry = dedup.absorb(state_object, alert(repeat=1, severity="low"), NOW, POLICY)
    assert entry["count"] == 3
    assert entry["escalated"] is True
    assert entry["notified"] is False   # fresh notification is required
    assert "escalated" in entry["notes"]


def test_notified_is_not_reset_by_ordinary_repeats():
    entry = dedup.absorb(state_object := state(), alert(severity="critical"), NOW, POLICY)
    assert entry["escalated"] is True
    entry["notified"] = True

    dedup.absorb(state_object, alert(severity="critical"), NOW, POLICY)
    assert entry["notified"] is True


def test_escalate_severity_floor_uses_rank():
    critical = alert(severity="critical")
    low = alert(severity="low")
    entry = dedup.absorb(state_object := state(), critical, NOW, POLICY)
    assert dedup.escalate(state_object, critical, POLICY) is True
    assert entry["escalated"] is True

    other = state()
    dedup.absorb(other, alert(severity="low", entity="api-2"), NOW, POLICY)
    assert dedup.escalate(other, alert(severity="low", entity="api-2"), POLICY) is False


def test_escalate_without_severity_floor_only_uses_threshold():
    policy = {"window_seconds": 60, "escalate_after": 2}
    st = state()
    critical = alert(severity="critical")
    entry = dedup.absorb(st, critical, NOW, policy)
    assert entry["escalated"] is False
    dedup.absorb(st, critical, NOW, policy)
    assert dedup.escalate(st, critical, policy) is True


def test_same_fingerprint_new_window_opens_a_new_main():
    st = state()
    first = alert(alert_id="old", at=NOW)
    later = alert(alert_id="new", at=NOW + timedelta(seconds=120))

    old_entry = dedup.absorb(st, first, NOW, POLICY)
    new_entry = dedup.absorb(st, later, later["timestamp"], POLICY)

    assert len(st["entries"]) == 1
    assert st["sequence"] == 2
    assert new_entry["alert_id"] == "new"
    assert new_entry["count"] == 1
    assert new_entry["window"] == old_entry["window"] + 2


def test_release_expired_releases_old_fingerprints():
    st = state()
    key = dedup.fingerprint(alert())
    dedup.absorb(st, alert(), NOW, POLICY)

    released = dedup.release_expired(st, NOW + timedelta(seconds=120), POLICY)
    assert released == 1
    assert st["entries"] == {}

    # Same fingerprint in a new window starts a brand-new main alert.
    entry = dedup.absorb(st, alert(alert_id="fresh"), NOW + timedelta(seconds=120), POLICY)
    assert key in st["entries"]
    assert entry["alert_id"] == "fresh"
    assert entry["count"] == 1
    assert st["sequence"] == 2


def test_release_keeps_current_window_fingerprints():
    st = state()
    dedup.absorb(st, alert(), NOW, POLICY)
    assert dedup.release_expired(st, NOW, POLICY) == 0
    assert dedup.fingerprint(alert()) in st["entries"]


def test_batches_start_fresh_and_do_not_inherit_counts():
    first = alert(alert_id="a-1", repeat=2)
    second = alert(alert_id="a-2", repeat=3)
    result = dedup.dedup_batch([[first], [second]], NOW, POLICY)
    key = dedup.fingerprint(first)

    assert result["batches"][0]["counts"][key] == 2
    assert result["batches"][1]["counts"][key] == 3
    assert result["batches"][0]["mains"][key] == "a-1"
    assert result["batches"][1]["mains"][key] == "a-2"
    assert [b["fingerprints"] for b in result["batches"]] == [[key], [key]]


def test_dedup_is_idempotent():
    batches = [
        [alert(alert_id="a"), alert(alert_id="b", severity="critical"), alert(alert_id="c", repeat=2)],
        [alert(alert_id="d", severity="low"), alert(alert_id="e", severity="low")],
    ]
    first = dedup.dedup_batch(batches, NOW, POLICY)
    second = dedup.dedup_batch(batches, NOW, POLICY)
    assert first == second


def test_dedup_loses_no_fingerprint():
    batches = [[
        alert(entity="api-1", severity="low"),
        alert(entity="api-1", severity="low", alert_id="dupe"),
        alert(entity="api-2", severity="critical"),
        alert(entity="api-2", severity="high"),
        alert(entity="api-1", rule="xss", severity="low"),
    ]]
    result = dedup.dedup_batch(batches, NOW, POLICY)
    summary = result["batches"][0]
    expected = {dedup.fingerprint(a) for a in batches[0]}
    assert expected <= set(summary["fingerprints"])
    assert set(summary["counts"]) == expected
    assert set(summary["mains"]) == expected


def test_validate_state_reports_negative_count_reversed_window_and_missing_fingerprint():
    st = {
        "entries": {
            "ok|rule|low": {
                "fingerprint": "ok|rule|low",
                "count": 1,
                "window": 0,
                "window_seconds": 60,
                "first_seen": NOW,
                "last_seen": NOW,
            },
            "neg|rule|low": {
                "fingerprint": "neg|rule|low",
                "count": -1,
                "window": 0,
                "window_seconds": 60,
                "first_seen": NOW,
                "last_seen": NOW,
            },
            "rev|rule|low": {
                "fingerprint": "rev|rule|low",
                "count": 1,
                "window": 0,
                "window_seconds": 60,
                "first_seen": NOW + timedelta(seconds=120),
                "last_seen": NOW,
            },
            "nofp|rule|low": {
                "count": 1,
                "window": 0,
                "window_seconds": 60,
                "first_seen": NOW,
                "last_seen": NOW,
            },
        },
        "sequence": 4,
    }
    problems = dedup.validate_state(st)
    assert len(problems) == 3
    joined = " ".join(problems).lower()
    assert "negative" in joined
    assert "reversed" in joined
    assert "missing fingerprint" in joined
