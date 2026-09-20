from __future__ import annotations

from .inventory import is_visible
from .models import Coverage, SigmaRule, TechniqueResult


def _data_source_hit(technique_data_sources: list, available: list) -> bool:
    if not technique_data_sources or not available:
        return False
    return any(
        avail.lower() in ds.lower() or ds.lower() in avail.lower()
        for ds in technique_data_sources
        for avail in available
    )


def score(
    rules: list[SigmaRule],
    inventory_sources: list,
    data_sources_available: list,
    attack_meta: dict | None = None,
) -> dict[str, TechniqueResult]:
    results: dict[str, TechniqueResult] = {}

    def get_or_create(technique_id: str) -> TechniqueResult:
        if technique_id not in results:
            meta = (attack_meta or {}).get(technique_id, {})
            results[technique_id] = TechniqueResult(
                technique_id=technique_id,
                name=meta.get("name", ""),
                tactics=meta.get("tactics", []),
                data_sources=meta.get("data_sources", []),
            )
        return results[technique_id]

    for rule in rules:
        if rule.status.strip().casefold() in {"deprecated", "unsupported"}:
            continue
        label = rule.title or rule.rule_id or rule.path
        for technique_id in rule.technique_ids:
            result = get_or_create(technique_id)
            result.rules.append(label)
            if is_visible(rule.logsource, inventory_sources):
                result.visible_rules.append(label)
            else:
                result.blind_rules.append(label)

    if attack_meta:
        for technique_id in attack_meta:
            get_or_create(technique_id)

    for result in results.values():
        if result.visible_rules:
            result.coverage = Coverage.DETECTED_VISIBLE
            result.reason = (
                f"{len(result.visible_rules)} rule(s) map to telemetry you collect"
            )
        elif result.blind_rules:
            result.coverage = Coverage.DETECTED_BLIND
            result.reason = (
                f"{len(result.blind_rules)} rule(s) exist but required telemetry "
                "is not in your inventory -- false confidence"
            )
        elif _data_source_hit(result.data_sources, data_sources_available):
            result.coverage = Coverage.VISIBLE_UNDETECTED
            result.reason = "telemetry looks available but no rule detects this technique"
        else:
            result.coverage = Coverage.NO_COVERAGE
            result.reason = "no rule and no known telemetry for this technique"

    return results
