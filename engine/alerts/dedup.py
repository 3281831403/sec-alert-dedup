"""De-duplication engine for security alerts.

Alerts are grouped by fingerprint. One main alert is kept per fingerprint
inside a sliding time window; repeats are absorbed into that main alert with
their counts accumulated, and escalations are flagged so that the notifier can
raise a fresh notification.
"""

from __future__ import annotations

from datetime import datetime

_EPOCH = datetime(1970, 1, 1)

# Severity labels, ordered from lowest to highest escalation priority.
SEVERITY_ORDER = ("low", "medium", "high", "critical")

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


def _alert_moment(alert, now):
    """Timestamp of an alert, falling back to the supplied current time."""
    stamp = alert.get("timestamp")
    if isinstance(stamp, str) and not stamp.strip():
        stamp = None
    return _as_datetime(stamp if stamp is not None else now)


def _repeat(alert):
    """Repeat count carried by an alert, defaulting to one."""
    value = alert.get("repeat", 1)
    if value is None:
        return 1
    return int(value)


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
    return int((moment - _EPOCH).total_seconds() // span)


def _new_state():
    return {"entries": {}, "sequence": 0}


def _threshold(policy):
    value = policy.get("escalate_after")
    if value is None:
        return _DEFAULT_ESCALATE_AFTER
    return int(value)


def _mark_escalated(entry):
    """Flag an escalated main alert and queue a fresh notification."""
    entry["escalated"] = True
    entry["notified"] = False
    notes = entry.setdefault("notes", [])
    if "escalated" not in notes:
        notes.append("escalated")


def severity_rank(severity):
    """Return the ordering weight of a severity label."""
    name = str(severity or "").strip().lower()
    if name in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(name)
    return len(SEVERITY_ORDER)


def fingerprint(alert):
    """Identity of an alert: its entity, rule and severity."""
    entity = str(alert.get("entity", "")).strip().lower()
    rule = str(alert.get("rule", "")).strip().lower()
    severity = str(alert.get("severity", "")).strip().lower()
    return f"{entity}|{rule}|{severity}"


def window_of(alert, now, window):
    """Number of the window that the alert timestamp falls into."""
    span = _span(window)
    stamp = alert.get("timestamp")
    if isinstance(stamp, str) and not stamp.strip():
        stamp = None
    moment = _as_datetime(stamp if stamp is not None else now)
    return _index(moment, span)


def escalate(state, alert, policy):
    """Whether the main alert behind this alert has reached escalation."""
    entry = state.get("entries", {}).get(fingerprint(alert))
    if entry is None:
        return False

    if int(entry.get("count", 0)) >= _threshold(policy):
        return True

    floor = policy.get("escalate_severity")
    if floor:
        severity = entry.get("severity", alert.get("severity", ""))
        return severity_rank(severity) >= severity_rank(floor)
    return False


def release_expired(state, now, policy):
    """Retire fingerprints whose window has slid past the current window.

    Returns the number of fingerprints that were released.
    """
    span = _span(policy)
    current = _index(_as_datetime(now), span)
    entries = state.get("entries", {})
    released = 0
    for key in list(entries):
        window = entries[key].get("window")
        if window is None:
            continue
        if int(window) < current:
            del entries[key]
            released += 1
    return released


def absorb(state, alert, now, policy):
    """Fold an alert into its main alert and return that main alert."""
    key = fingerprint(alert)
    span = _span(policy)
    moment = _alert_moment(alert, now)
    current = _index(moment, span)
    entries = state.setdefault("entries", {})
    entry = entries.get(key)

    if entry is None or entry.get("window") != current:
        entry = _open_entry(key, alert, now, policy)
        entries[key] = entry
        state["sequence"] = int(state.get("sequence", 0)) + 1
        if escalate(state, alert, policy):
            _mark_escalated(entry)
        return entry

    first = entry.get("first_seen")
    if first is None or moment < first:
        entry["first_seen"] = moment
    last = entry.get("last_seen")
    if last is None or moment > last:
        entry["last_seen"] = moment
    entry["count"] = int(entry.get("count", 0)) + _repeat(alert)
    if not entry.get("escalated") and escalate(state, alert, policy):
        _mark_escalated(entry)
    return entry


def _open_entry(key, alert, now, policy):
    """Create the main alert that a fingerprint starts a window with."""
    stamp = _alert_moment(alert, now)
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
        "count": _repeat(alert),
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

        try:
            count = int(entry.get("count", 0))
        except (TypeError, ValueError):
            problems.append(f"invalid count for entry {key}")
        else:
            if count < 0:
                problems.append(f"negative count for entry {key}")

        first = entry.get("first_seen")
        last = entry.get("last_seen")
        reversed_order = False
        if first is not None and last is not None and last < first:
            reversed_order = True

        span = entry.get("window_seconds")
        window = entry.get("window")
        if span and window is not None and last is not None:
            span = int(span)
            # A main alert cannot sit in a window that starts after its last
            # observed alert; that would mean the window ordering is reversed.
            # A main alert cannot claim a window later than the window its last
            # observed alert falls into; that would mean the order is reversed.
            if span > 0 and int(window) > _index(_as_datetime(last), span):
                reversed_order = True

        if reversed_order:
            problems.append(f"window order reversed for entry {key}")
    return problems


def dedup_batch(batches, now, policy):
    """De-duplicate every batch and return one summary per batch.

    Each batch starts from an empty state, so repeated alerts in one batch
    never inherit counts (or main alerts) from an earlier batch.
    """
    summaries = []
    last_entries = {}
    for batch in batches:
        state = _new_state()
        for alert in batch:
            absorb(state, alert, now, policy)
        summaries.append(_summary(state))
        last_entries = state["entries"]
    return {"batches": summaries, "entries": last_entries}


def _summary(state):
    """Per-batch view of the fingerprints, repeat counts and main alerts."""
    entries = state.get("entries", {})
    return {
        "fingerprints": sorted(entries),
        "counts": {key: int(entry.get("count", 0)) for key, entry in entries.items()},
        "mains": {key: entry.get("alert_id", key) for key, entry in entries.items()},
    }
