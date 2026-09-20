"""Telemetry inventory: what you actually collect, in a format attackgap
defines itself (plain JSON, no third-party schema involved).

    {
      "sources": [
        {"product": "windows", "service": "sysmon",
         "categories": ["process_creation", "network_connection"]},
        {"product": "linux", "categories": ["auth"]},
        {"service": "cloudtrail", "categories": ["*"]}
      ],
      "data_sources": [
        "Process: Process Creation",
        "Command: Command Execution"
      ]
    }

``sources`` entries are matched against a Sigma rule's ``logsource`` block
to decide whether a rule that exists can actually fire (its telemetry is
collected). ``data_sources`` is free text matched against ATT&CK
``x_mitre_data_sources`` strings (when an ATT&CK STIX file is supplied) to
find techniques you have telemetry for but no rule covers.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_inventory(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("inventory root must be a JSON object")
    data.setdefault("sources", [])
    data.setdefault("data_sources", [])

    if not isinstance(data["sources"], list):
        raise ValueError("inventory 'sources' must be a list")
    if not isinstance(data["data_sources"], list) or not all(
        isinstance(item, str) for item in data["data_sources"]
    ):
        raise ValueError("inventory 'data_sources' must be a list of strings")

    for index, source in enumerate(data["sources"]):
        if not isinstance(source, dict):
            raise ValueError(f"inventory source #{index + 1} must be an object")
        if not any(source.get(field) for field in ("product", "service", "categories")):
            raise ValueError(
                f"inventory source #{index + 1} must define product, service, or categories"
            )
        for field in ("product", "service"):
            if field in source and not isinstance(source[field], str):
                raise ValueError(f"inventory source #{index + 1} '{field}' must be a string")
        categories = source.get("categories", [])
        if not isinstance(categories, list) or not all(isinstance(item, str) for item in categories):
            raise ValueError(
                f"inventory source #{index + 1} 'categories' must be a list of strings"
            )
    return data


def entry_matches(rule_logsource: dict, entry: dict) -> bool:
    for field_name in ("product", "service"):
        wanted = entry.get(field_name)
        have = rule_logsource.get(field_name)
        if wanted and have and wanted.strip().casefold() != have.strip().casefold():
            return False
        if wanted and not have:
            return False

    categories = {category.strip().casefold() for category in entry.get("categories") or []}
    rule_category = rule_logsource.get("category")
    if categories and "*" not in categories:
        if not rule_category or rule_category.strip().casefold() not in categories:
            return False

    return True


def is_visible(rule_logsource: dict, inventory_sources: list) -> bool:
    if not rule_logsource:
        return False
    return any(entry_matches(rule_logsource, entry) for entry in inventory_sources)
