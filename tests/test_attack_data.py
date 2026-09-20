from pathlib import Path

from attackgap.attack_data import load_attack_stix

FIXTURE = Path(__file__).parent / "fixtures" / "attack_sample.json"


def test_load_attack_stix_extracts_expected_fields():
    meta = load_attack_stix(FIXTURE)
    assert set(meta) == {"T1059.001", "T1078", "T1053.005", "T1499"}
    assert meta["T1059.001"]["name"] == "Command and Scripting Interpreter: PowerShell"
    assert meta["T1059.001"]["tactics"] == ["execution"]
    assert "Process: Process Creation" in meta["T1059.001"]["data_sources"]


def test_load_attack_stix_skips_deprecated():
    meta = load_attack_stix(FIXTURE)
    assert "T9999" not in meta


def test_load_attack_stix_skips_malformed_objects(tmp_path):
    path = tmp_path / "attack.json"
    path.write_text(
        '{"objects": [null, "bad", {"type": "attack-pattern", "external_references": [null]}]}',
        encoding="utf-8",
    )
    assert load_attack_stix(path) == {}
