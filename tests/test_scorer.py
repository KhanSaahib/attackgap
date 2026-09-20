from pathlib import Path

from attackgap.attack_data import load_attack_stix
from attackgap.inventory import load_inventory
from attackgap.models import Coverage, SigmaRule
from attackgap.scorer import score
from attackgap.sigma_reader import load_rules

FIXTURES = Path(__file__).parent / "fixtures"


def _run(with_attack_data: bool):
    rules = load_rules(FIXTURES / "rules")
    inventory = load_inventory(FIXTURES / "inventory.json")
    attack_meta = load_attack_stix(FIXTURES / "attack_sample.json") if with_attack_data else None
    return score(
        rules,
        inventory_sources=inventory["sources"],
        data_sources_available=inventory["data_sources"],
        attack_meta=attack_meta,
    )


def test_mixed_visibility_rounds_up_to_detected_visible():
    # T1059.001 has one visible rule (windows/sysmon) and one blind rule
    # (linux) -- any working rule means the technique is DETECTED_VISIBLE.
    results = _run(with_attack_data=False)
    assert results["T1059.001"].coverage == Coverage.DETECTED_VISIBLE
    assert len(results["T1059.001"].visible_rules) == 1
    assert len(results["T1059.001"].blind_rules) == 1


def test_blind_only_technique():
    results = _run(with_attack_data=False)
    assert results["T1078"].coverage == Coverage.DETECTED_BLIND


def test_without_attack_data_only_rule_driven_techniques_appear():
    results = _run(with_attack_data=False)
    assert set(results) == {"T1059.001", "T1078"}


def test_with_attack_data_finds_visible_undetected_and_no_coverage():
    results = _run(with_attack_data=True)
    assert results["T1053.005"].coverage == Coverage.VISIBLE_UNDETECTED
    assert results["T1499"].coverage == Coverage.NO_COVERAGE
    assert results["T1059.001"].coverage == Coverage.DETECTED_VISIBLE
    assert results["T1059.001"].name == "Command and Scripting Interpreter: PowerShell"


def test_deprecated_and_unsupported_rules_do_not_count_as_coverage():
    rules = [
        SigmaRule("deprecated.yml", status="deprecated", technique_ids=["T1059.001"]),
        SigmaRule("unsupported.yml", status="unsupported", technique_ids=["T1078"]),
    ]
    assert score(rules, [], [], None) == {}
