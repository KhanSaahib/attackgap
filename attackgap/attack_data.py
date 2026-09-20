"""Optional reader for a locally-downloaded MITRE ATT&CK Enterprise STIX
bundle (get one yourself from
https://github.com/mitre-attack/attack-stix-data -- nothing from that
dataset is bundled with attackgap). Only used to resolve technique
names/tactics/data-sources; attackgap works without it, just with less
context in the report.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_attack_stix(path: Path) -> dict:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = raw.get("objects", []) if isinstance(raw, dict) else raw

    result: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue

        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        result[technique_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "data_sources": obj.get("x_mitre_data_sources", []),
        }

    return result
