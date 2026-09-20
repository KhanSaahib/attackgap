from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Coverage(str, Enum):
    DETECTED_VISIBLE = "detected_visible"
    DETECTED_BLIND = "detected_blind"
    VISIBLE_UNDETECTED = "visible_undetected"
    NO_COVERAGE = "no_coverage"


COVERAGE_SCORE = {
    Coverage.DETECTED_VISIBLE: 100,
    Coverage.DETECTED_BLIND: 50,
    Coverage.VISIBLE_UNDETECTED: 25,
    Coverage.NO_COVERAGE: 0,
}

# Colors are chosen for contrast against the Navigator's default light
# background rather than pulled from any project's palette.
COVERAGE_COLOR = {
    Coverage.DETECTED_VISIBLE: "#8ec843",
    Coverage.DETECTED_BLIND: "#ffb347",
    Coverage.VISIBLE_UNDETECTED: "#66b3ff",
    Coverage.NO_COVERAGE: "#ff6666",
}


@dataclass
class SigmaRule:
    path: str
    title: str = ""
    rule_id: str = ""
    status: str = ""
    logsource: dict = field(default_factory=dict)
    technique_ids: list = field(default_factory=list)


@dataclass
class TechniqueResult:
    technique_id: str
    name: str = ""
    tactics: list = field(default_factory=list)
    coverage: Coverage = Coverage.NO_COVERAGE
    rules: list = field(default_factory=list)
    visible_rules: list = field(default_factory=list)
    blind_rules: list = field(default_factory=list)
    data_sources: list = field(default_factory=list)
    reason: str = ""
