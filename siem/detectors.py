"""Detection engine for the SIEM platform."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, Iterator

from .models import Alert, DetectionRule, Event


class DetectionEngine:
    """Evaluates events against loaded rules to produce alerts."""

    def __init__(self, rules: Iterable[DetectionRule]):
        self.rules = [rule for rule in rules if rule.enabled]
        self.state: Dict[str, Dict[str, Deque[Event]]] = defaultdict(lambda: defaultdict(deque))

    def process(self, events: Iterable[Event]) -> Iterator[Alert]:
        for event in events:
            for rule in self.rules:
                handler = _HANDLERS.get(rule.rule_type)
                if not handler:
                    continue
                yield from handler(self.state[rule.id], rule, event)


# --- Detection handlers ---------------------------------------------------


def _handle_failed_login(state: Dict[str, Deque[Event]], rule: DetectionRule, event: Event) -> Iterator[Alert]:
    params = rule.parameters
    category = params.get("event_category", "auth")
    match_field = params.get("match_field", "result")
    match_value = params.get("match_value", "failed")
    group_by = params.get("group_by", "username")
    threshold = int(params.get("threshold", 5))
    window_minutes = int(params.get("window_minutes", 10))

    if event.category != category:
        return
    if event.details.get(match_field) != match_value:
        return

    key = event.details.get(group_by, "unknown")
    bucket = state[key]
    bucket.append(event)
    _evict_old(bucket, event.timestamp, window_minutes)

    if len(bucket) >= threshold:
        yield Alert(
            id=f"{rule.id}:{key}:{int(event.timestamp.timestamp())}",
            created_at=datetime.utcnow(),
            title=f"{rule.name} for {key}",
            description=(
                f"Detected {len(bucket)} failed logins for {key} within {window_minutes} minutes."
            ),
            priority=rule.severity,
            events=list(bucket),
            remediation=rule.remediation,
        )
        bucket.clear()


def _handle_port_scan(state: Dict[str, Deque[Event]], rule: DetectionRule, event: Event) -> Iterator[Alert]:
    params = rule.parameters
    category = params.get("event_category", "network")
    group_by = params.get("group_by", "src_ip")
    distinct_field = params.get("distinct_field", "dest_port")
    threshold = int(params.get("threshold", 15))
    window_minutes = int(params.get("window_minutes", 5))

    if event.category != category:
        return

    key = event.details.get(group_by, "unknown")
    bucket = state[key]
    bucket.append(event)
    _evict_old(bucket, event.timestamp, window_minutes)

    unique_values = {e.details.get(distinct_field) for e in bucket}
    if len(unique_values) >= threshold:
        yield Alert(
            id=f"{rule.id}:{key}:{int(event.timestamp.timestamp())}",
            created_at=datetime.utcnow(),
            title=f"{rule.name} from {key}",
            description=(
                f"Observed potential port scan with {len(unique_values)} unique {distinct_field} values."
            ),
            priority=rule.severity,
            events=list(bucket),
            remediation=rule.remediation,
        )
        bucket.clear()


def _handle_dns_anomaly(state: Dict[str, Deque[Event]], rule: DetectionRule, event: Event) -> Iterator[Alert]:
    params = rule.parameters
    category = params.get("event_category", "dns")
    length_threshold = int(params.get("length_threshold", 45))
    entropy_threshold = float(params.get("entropy_threshold", 3.5))

    if event.category != category:
        return

    domain = event.details.get("query")
    if not domain:
        return

    if len(domain) >= length_threshold or _shannon_entropy(domain) >= entropy_threshold:
        yield Alert(
            id=f"{rule.id}:{domain}:{int(event.timestamp.timestamp())}",
            created_at=datetime.utcnow(),
            title=f"{rule.name} - suspicious domain {domain}",
            description=(
                "Detected DNS query that may indicate tunneling activity due to long or high entropy domain name."
            ),
            priority=rule.severity,
            events=[event],
            remediation=rule.remediation,
        )


_HANDLERS = {
    "failed_login_threshold": _handle_failed_login,
    "port_scan": _handle_port_scan,
    "dns_anomaly": _handle_dns_anomaly,
}


def _evict_old(bucket: Deque[Event], current_ts: datetime, window_minutes: int) -> None:
    cutoff = current_ts - timedelta(minutes=window_minutes)
    while bucket and bucket[0].timestamp < cutoff:
        bucket.popleft()


def _shannon_entropy(value: str) -> float:
    import math

    counts: Dict[str, int] = defaultdict(int)
    for char in value:
        counts[char] += 1
    entropy = 0.0
    for count in counts.values():
        p = count / len(value)
        entropy -= p * math.log2(p)
    return entropy
