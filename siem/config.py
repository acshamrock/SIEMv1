"""Configuration loading utilities for the SIEM platform."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

try:
    import yaml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    yaml = None

from .models import DetectionRule


class ConfigurationError(RuntimeError):
    """Raised when configuration files are invalid."""


def load_rules(paths: Iterable[Path]) -> List[DetectionRule]:
    """Load detection rules from YAML or JSON files.

    Args:
        paths: Iterable of file paths to parse.

    Returns:
        List of :class:`DetectionRule` objects.
    """

    rules: List[DetectionRule] = []
    for path in paths:
        if not path.exists():
            raise ConfigurationError(f"Rule file {path} does not exist")
        data = _parse_file(path)
        if not isinstance(data, list):
            raise ConfigurationError(f"Rule file {path} must contain a list")
        for item in data:
            rules.append(_parse_rule(item, path))
    return rules


def _parse_file(path: Path):
    if path.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise ConfigurationError(
                "PyYAML is not installed. Install it or use JSON rule files instead."
            )
        return yaml.safe_load(path.read_text())
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text())
    raise ConfigurationError(f"Unsupported rule file format: {path.suffix}")


def _parse_rule(data: dict, path: Path) -> DetectionRule:
    required_fields = {"id", "name", "rule_type", "description", "severity", "enabled", "parameters"}
    missing = required_fields - data.keys()
    if missing:
        raise ConfigurationError(f"Rule in {path} missing required fields: {missing}")
    return DetectionRule(
        id=str(data["id"]),
        name=str(data["name"]),
        rule_type=str(data["rule_type"]),
        description=str(data["description"]),
        severity=str(data["severity"]),
        enabled=bool(data["enabled"]),
        parameters=dict(data["parameters"]),
        remediation=data.get("remediation"),
    )
