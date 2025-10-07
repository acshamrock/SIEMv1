"""Log ingestion utilities for the SIEM platform."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .models import Event


class LogIngestionError(RuntimeError):
    """Raised when logs cannot be parsed."""


def read_log_files(paths: Iterable[Path], tzinfo=None) -> Iterator[Event]:
    """Read newline-delimited JSON log files and yield :class:`Event` objects."""

    for path in paths:
        if not path.exists():
            raise LogIngestionError(f"Log file {path} does not exist")
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LogIngestionError(f"Invalid JSON in {path}: {exc}") from exc
            event = _normalize_event(data, source=str(path), tzinfo=tzinfo)
            if event:
                yield event


def _normalize_event(data: dict, source: str, tzinfo=None) -> Optional[Event]:
    timestamp = _parse_timestamp(data.get("timestamp"), tzinfo=tzinfo)
    if not timestamp:
        return None
    category = data.get("category", "unknown")
    severity = data.get("severity", "info")
    details = {
        key: str(value)
        for key, value in data.items()
        if key not in {"timestamp", "category", "severity"}
    }
    return Event(
        timestamp=timestamp,
        source=source,
        category=category,
        severity=severity,
        details=details,
    )


def _parse_timestamp(value, tzinfo=None) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=tzinfo)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(str(value), fmt).replace(tzinfo=tzinfo)
        except ValueError:
            continue
    return None
