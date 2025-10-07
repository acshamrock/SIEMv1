"""Command-line interface for the SIEM platform."""
from __future__ import annotations

import argparse
from pathlib import Path

from .alerting import AlertDispatcher
from .config import ConfigurationError, load_rules
from .detectors import DetectionEngine
from .log_sources import LogIngestionError, read_log_files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Home network SIEM")
    parser.add_argument("--logs", nargs="+", type=Path, required=True, help="Paths to log files")
    parser.add_argument("--rules", nargs="+", type=Path, required=True, help="Paths to rule files")
    parser.add_argument("--alert-dir", type=Path, default=None, help="Directory to store alert JSON files")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        rules = load_rules(args.rules)
    except ConfigurationError as exc:
        print(f"Error loading rules: {exc}")
        return 1

    engine = DetectionEngine(rules)
    dispatcher = AlertDispatcher(args.alert_dir)

    try:
        events = list(read_log_files(args.logs))
    except LogIngestionError as exc:
        print(f"Error reading logs: {exc}")
        return 2

    alerts = list(engine.process(events))
    dispatcher.dispatch(alerts)
    print(f"Processed {len(events)} events and generated {len(alerts)} alerts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
