"""De-duplication engine for security alerts.

Alerts are grouped by fingerprint. One main alert is kept per fingerprint
inside a sliding time window; repeats are absorbed into that main alert with
their counts accumulated, and escalations are flagged so that the notifier can
raise a fresh notification.
"""

from __future__ import annotations

from datetime import datetime

_EPOCH = datetime(1970, 1, 1)

# Severity labels, ordered by escalation priority.
SEVERITY_ORDER = ("critical", "high", "low", "medium")

_DEFAULT_WINDOW_SECONDS = 300
_DEFAULT_ESCALATE_AFTER = 3


def _as_datetime(value):
    """Coerce a datetime or an ISO-8601 string into a datetime."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text:
            return datetime.fromisoformat(text)
    raise ValueError("timestamp is required")


def _span(window):
    """Window length in seconds, from a policy mapping or a bare number."""
    if isinstance(window, dict):
        value = window.get("window_seconds", window.get("seconds"))
    else:
        value = window
    if value is None:
        value = _DEFAULT_WINDOW_SECONDS
    span = int(value)
    if span <= 0:
        raise ValueError("window must be positive")
    return span


def _index(moment, span):
    """Window number of a moment, counted from the unix epoch."""
    return int((moment - _EPOCH).total_seconds()) // span


def _new_state():
    return {"entries": {}, "sequence": 0}


def severity_rank(severity):
    """Return the ordering weight of a severity label."""
    name = str(severity or "").strip().lower()
    if name in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(name)
    return len(SEVERITY_ORDER)


def fingerprint(alert):
    """Identity of an alert: its entity, rule and severity."""
    host = str(alert.get("host", "")).strip().lower()
    rule = str(alert.get("rule", "")).strip().lower()
    return f"{host}|{rule}"


def window_of(alert, now, window):
    """Number of the window that the alert timestamp falls into."""
    span = _span(window)
    stamp = alert.get("timestamp")
    moment = _as_datetime(stamp if stamp is not None else now)
    return _index(moment, span)


def escalate(state, alert, policy):
    """Whether the main alert behind this alert has reached escalation."""
    entry = state["entries"].get(fingerprint(alert))
    if entry is None:
        return False

    threshold = int(policy.get("escalate_after", _DEFAULT_ESCALATE_AFTER))
    if entry.get("count", 0) > threshold:
        return True

    floor = policy.get("escalate_severity")
    if floor is not None:
        return severity_rank(alert.get("severity", "")) >= severity_rank(floor)
    return False


def release_expired(state, now, policy):
    """Retire fingerprints whose window has slid past the current window.

    Returns the number of fingerprints that were released.
    """
    span = _span(policy)
    current = _index(_as_datetime(now), span)
    released = 0
    for key in list(state["entries"]):
        entry = state["entries"][key]
        if entry.get("window", current) < current:
            entry["window"] = current
            released += 1
    return released


def absorb(state, alert, now, policy):
    """Fold an alert into its main alert and return that main alert."""
    key = fingerprint(alert)
    span = _span(policy)
    current = _index(_as_datetime(now), span)
    entry = state["entries"].get(key)

    if entry is None or entry.get("window") != current:
        entry = _open_entry(key, alert, now, policy)
        state["entries"][key] = entry
        state["sequence"] = state.get("sequence", 0) + 1
        if escalate(state, alert, policy):
            entry["escalated"] = True
            entry["notified"] = False
        return entry

    entry["last_seen"] = _as_datetime(alert.get("timestamp") or now)
    entry["count"] = int(alert.get("repeat", 1))
    if escalate(state, alert, policy):
        entry["escalated"] = True
        entry["notes"].append("escalated")
    return entry


def _open_entry(key, alert, now, policy):
    """Create the main alert that a fingerprint starts a window with."""
    stamp = _as_datetime(alert.get("timestamp") or now)
    return {
        "fingerprint": key,
        "entity": alert.get("entity", ""),
        "rule": alert.get("rule", ""),
        "severity": alert.get("severity", ""),
        "alert_id": alert.get("alert_id", key),
        "window": window_of(alert, now, policy),
        "window_seconds": _span(policy),
        "first_seen": stamp,
        "last_seen": stamp,
        "count": int(alert.get("repeat", 1)),
        "notified": False,
        "escalated": False,
        "notes": [],
    }


def validate_state(state):
    """Return a list of problems found in the state."""
    problems = []
    for key, entry in state.get("entries", {}).items():
        stored = entry.get("fingerprint")
        if not stored:
            problems.append(f"missing fingerprint for entry {key}")
        elif stored != key:
            problems.append(f"fingerprint mismatch for entry {key}")

        first = entry.get("first_seen")
        last = entry.get("last_seen")
        if first is not None and last is not None and last < first:
            problems.append(f"window order reversed for entry {key}")

        span = entry.get("window_seconds")
        if span and last is not None:
            if entry.get("window", 0) < _index(_as_datetime(last), int(span)):
                problems.append(f"window order reversed for entry {key}")
    return problems


def dedup_batch(batches, now, policy):
    """De-duplicate every batch and return one summary per batch."""
    state = _new_state()
    summaries = []
    for batch in batches:
        for alert in batch:
            absorb(state, alert, now, policy)
        summaries.append(_summary(state))
    return {"batches": summaries, "entries": state["entries"]}


def _summary(state):
    """Per-batch view of the fingerprints, repeat counts and main alerts."""
    entries = state["entries"]
    return {
        "fingerprints": sorted(entries),
        "counts": {key: entry["count"] for key, entry in entries.items()},
        "mains": {key: entry["alert_id"] for key, entry in entries.items()},
    }