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
