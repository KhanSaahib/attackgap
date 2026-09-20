from pathlib import Path

from attackgap.sigma_reader import load_rules, normalize_technique, parse_sigma_file, parse_sigma_text

FIXTURES = Path(__file__).parent / "fixtures" / "rules"


def test_normalize_technique():
    assert normalize_technique("attack.t1059.001") == "T1059.001"
    assert normalize_technique("attack.T1078") == "T1078"
    assert normalize_technique("attack.execution") is None
    assert normalize_technique("attack.defense_evasion") is None


def test_parse_sigma_file_block_tags_and_logsource():
    rule = parse_sigma_file(FIXTURES / "powershell.yml")
    assert rule.title == "Suspicious PowerShell Execution"
    assert rule.rule_id == "11111111-1111-1111-1111-111111111111"
    assert rule.logsource == {
        "product": "windows",
        "service": "sysmon",
        "category": "process_creation",
    }
    assert rule.technique_ids == ["T1059.001"]


def test_parse_sigma_file_flow_style_tags_and_comment():
    rule = parse_sigma_file(FIXTURES / "dns_tunnel.yml")
    assert rule.logsource == {"category": "dns", "product": "zeek"}
    assert rule.technique_ids == ["T1078"]


def test_load_rules_reads_whole_directory():
    rules = load_rules(FIXTURES)
    assert len(rules) == 3
    all_ids = {tid for rule in rules for tid in rule.technique_ids}
    assert all_ids == {"T1059.001", "T1078"}


def test_inline_comments_are_removed_without_touching_quoted_hashes():
    rule = parse_sigma_text(
        'title: "PowerShell #1" # comment\n'
        "tags: [attack.t1059.001] # comment\n"
    )
    assert rule.title == "PowerShell #1"
    assert rule.technique_ids == ["T1059.001"]
