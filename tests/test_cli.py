import json
from pathlib import Path

from attackgap.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_end_to_end(tmp_path):
    layer_out = tmp_path / "layer.json"
    report_out = tmp_path / "report.md"

    exit_code = main(
        [
            "--rules",
            str(FIXTURES / "rules"),
            "--inventory",
            str(FIXTURES / "inventory.json"),
            "--attack-data",
            str(FIXTURES / "attack_sample.json"),
            "--layer-output",
            str(layer_out),
            "--report-output",
            str(report_out),
        ]
    )

    assert exit_code == 0
    layer = json.loads(layer_out.read_text())
    assert {t["techniqueID"] for t in layer["techniques"]} == {
        "T1059.001",
        "T1078",
        "T1053.005",
        "T1499",
    }

    report_text = report_out.read_text()
    assert "Detected but blind" in report_text
    assert "Visible but undetected" in report_text


def test_cli_missing_rules_dir_errors(tmp_path, capsys):
    exit_code = main(
        [
            "--rules",
            str(tmp_path / "does-not-exist"),
            "--inventory",
            str(FIXTURES / "inventory.json"),
        ]
    )
    assert exit_code == 2


def test_cli_reports_invalid_inventory(tmp_path, capsys):
    inventory = tmp_path / "inventory.json"
    inventory.write_text("[]", encoding="utf-8")
    exit_code = main(
        ["--rules", str(FIXTURES / "rules"), "--inventory", str(inventory)]
    )
    assert exit_code == 2
    assert "inventory root" in capsys.readouterr().err


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("expected SystemExit from argparse version action")
    assert "attackgap 0.1.0" in capsys.readouterr().out


def test_cli_empty_rules_directory_fails(tmp_path, capsys):
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"sources": []}', encoding="utf-8")
    exit_code = main(["--rules", str(tmp_path), "--inventory", str(inventory)])
    assert exit_code == 2
    assert "no Sigma" in capsys.readouterr().err


def test_cli_json_has_schema_and_summary(capsys):
    exit_code = main(
        [
            "--rules", str(FIXTURES / "rules"),
            "--inventory", str(FIXTURES / "inventory.json"),
            "--format", "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["schema_version"] == 1
    assert "detected_visible" in payload["summary"]
    assert "T1059.001" in payload["techniques"]


def test_cli_fail_on_blind_is_a_ci_gate(capsys):
    exit_code = main(
        [
            "--rules", str(FIXTURES / "rules"),
            "--inventory", str(FIXTURES / "inventory.json"),
            "--fail-on", "blind",
        ]
    )
    capsys.readouterr()
    assert exit_code == 1


def test_cli_fail_on_never_remains_zero(capsys):
    exit_code = main(
        [
            "--rules", str(FIXTURES / "rules"),
            "--inventory", str(FIXTURES / "inventory.json"),
            "--fail-on", "never",
        ]
    )
    capsys.readouterr()
    assert exit_code == 0
