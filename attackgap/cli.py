from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .attack_data import load_attack_stix
from .inventory import load_inventory
from .models import Coverage
from .navigator import build_layer
from .report import render_markdown
from .scorer import score
from .sigma_reader import load_rules

SCHEMA_VERSION = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attackgap",
        description="Offline MITRE ATT&CK detection-coverage gap mapper.",
    )
    parser.add_argument("--rules", required=True, type=Path, help="Directory of Sigma rule .yml/.yaml files")
    parser.add_argument("--inventory", required=True, type=Path, help="Path to a JSON telemetry inventory file")
    parser.add_argument(
        "--attack-data",
        type=Path,
        help="Optional local MITRE ATT&CK Enterprise STIX bundle JSON "
        "(adds technique names/tactics and finds visible-but-undetected gaps)",
    )
    parser.add_argument("--layer-output", type=Path, help="Write an ATT&CK Navigator layer JSON to this path")
    parser.add_argument("--report-output", type=Path, help="Write a markdown gap report to this path")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Format for stdout summary when --report-output is not given",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    rules_dir = args.rules
    if not rules_dir.is_dir():
        print(f"error: rules directory not found: {rules_dir}", file=sys.stderr)
        return 2

    inventory_path = args.inventory
    if not inventory_path.is_file():
        print(f"error: inventory file not found: {inventory_path}", file=sys.stderr)
        return 2

    try:
        rules = load_rules(rules_dir)
        inventory = load_inventory(inventory_path)
        attack_meta = load_attack_stix(args.attack_data) if args.attack_data else None
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"error: could not load input: {exc}", file=sys.stderr)
        return 2
    if not rules:
        print(f"error: no Sigma .yml or .yaml files found under {rules_dir}", file=sys.stderr)
        return 2

    results = score(
        rules,
        inventory_sources=inventory.get("sources", []),
        data_sources_available=inventory.get("data_sources", []),
        attack_meta=attack_meta,
    )

    if not results:
        print(
            "No ATT&CK-tagged techniques found in rules and no --attack-data "
            "supplied; nothing to report.",
            file=sys.stderr,
        )
        return 1

    if args.layer_output:
        layer = build_layer(results)
        try:
            args.layer_output.write_text(json.dumps(layer, indent=2), encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write layer output: {exc}", file=sys.stderr)
            return 2

    if args.format == "markdown":
        report_text = render_markdown(results)
    else:
        summary = {
            coverage.value: sum(1 for result in results.values() if result.coverage == coverage)
            for coverage in Coverage
        }
        report_text = json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
                "techniques": {
                    technique_id: {
                        "coverage": result.coverage.value,
                        "name": result.name,
                        "reason": result.reason,
                        "tactics": result.tactics,
                        "rules": result.rules,
                        "visible_rules": result.visible_rules,
                        "blind_rules": result.blind_rules,
                        "data_sources": result.data_sources,
                    }
                    for technique_id, result in results.items()
                },
            },
            indent=2,
        )

    if args.report_output:
        try:
            args.report_output.write_text(report_text, encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write report output: {exc}", file=sys.stderr)
            return 2
    else:
        print(report_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
