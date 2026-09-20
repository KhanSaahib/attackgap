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
    if isinstance(raw, dict):
        objects = raw.get("objects", [])
    elif isinstance(raw, list):
        objects = raw
    else:
        raise ValueError("ATT&CK data must be a STIX bundle object or a list of objects")
    if not isinstance(objects, list):
        raise ValueError("ATT&CK STIX 'objects' must be a list")

    result: dict[str, dict] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        references = obj.get("external_references", [])
        if not isinstance(references, list):
            references = []
        technique_id = None
        for ref in references:
            if not isinstance(ref, dict):
                continue
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not isinstance(technique_id, str) or not technique_id:
            continue

        phases = obj.get("kill_chain_phases", [])
        if not isinstance(phases, list):
            phases = []
        tactics = [
            phase.get("phase_name")
            for phase in phases
            if isinstance(phase, dict) and phase.get("kill_chain_name") == "mitre-attack"
        ]

        data_sources = obj.get("x_mitre_data_sources", [])
        if not isinstance(data_sources, list):
            data_sources = []

        result[technique_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "data_sources": data_sources,
        }

    return result
