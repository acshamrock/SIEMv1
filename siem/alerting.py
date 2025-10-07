"""Alert handling for the SIEM platform."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import Alert


class AlertDispatcher:
    """Dispatch alerts to stdout and optionally to disk."""

    def __init__(self, output_dir: Path | None = None):
        self.output_dir = output_dir
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def dispatch(self, alerts: Iterable[Alert]) -> None:
        for alert in alerts:
            self._print(alert)
            if self.output_dir:
                self._write(alert)

    def _print(self, alert: Alert) -> None:
        print("=" * 80)
        print(f"ALERT: {alert.title}")
        print(f"Priority: {alert.priority} | Created: {alert.created_at.isoformat()} | ID: {alert.id}")
        print(f"Description: {alert.description}")
        if alert.remediation:
            print(f"Remediation: {alert.remediation}")
        print(f"Associated events: {len(alert.events)}")
        for event in alert.events[:5]:
            print(f"  - {event.timestamp.isoformat()} {event.category} {event.details}")
        if len(alert.events) > 5:
            print(f"  ... {len(alert.events) - 5} more events omitted")
        print("=" * 80)

    def _write(self, alert: Alert) -> None:
        filename = f"{alert.id.replace(':', '_')}.json"
        payload = {
            "id": alert.id,
            "created_at": alert.created_at.isoformat(),
            "title": alert.title,
            "description": alert.description,
            "priority": alert.priority,
            "remediation": alert.remediation,
            "events": [
                {
                    "timestamp": event.timestamp.isoformat(),
                    "source": event.source,
                    "category": event.category,
                    "severity": event.severity,
                    "details": event.details,
                }
                for event in alert.events
            ],
        }
        (self.output_dir / filename).write_text(json.dumps(payload, indent=2))
