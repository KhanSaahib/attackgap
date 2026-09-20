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
    data.setdefault("sources", [])
    data.setdefault("data_sources", [])
    return data


def entry_matches(rule_logsource: dict, entry: dict) -> bool:
    for field_name in ("product", "service"):
        wanted = entry.get(field_name)
        have = rule_logsource.get(field_name)
        if wanted and have and wanted != have:
            return False
        if wanted and not have:
            return False

    categories = entry.get("categories") or []
    rule_category = rule_logsource.get("category")
    if categories and "*" not in categories:
        if not rule_category or rule_category not in categories:
            return False

    return True


def is_visible(rule_logsource: dict, inventory_sources: list) -> bool:
    if not rule_logsource:
        return False
    return any(entry_matches(rule_logsource, entry) for entry in inventory_sources)
