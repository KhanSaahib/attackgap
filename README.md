# attackgap

<p align="center">
  <img src="docs/assets/attackgap-social.png" alt="A security coverage map revealing a gap under a scanning beam" width="100%">
</p>

<p align="center">
  <a href="https://github.com/KhanSaahib/attackgap/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/KhanSaahib/attackgap/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-2563eb.svg"></a>
  <img alt="Offline first" src="https://img.shields.io/badge/network-offline--first-0891b2.svg">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-16a34a.svg"></a>
</p>

<p align="center"><strong>Measure whether your detections can actually see the techniques they claim to cover.</strong></p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#usage">Usage</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

> [!TIP]
> **Start here:** Run the fixture-backed [quick start](#quick-start). If it helps, [star this repo](https://github.com/KhanSaahib/attackgap) and [follow @KhanSaahib](https://github.com/KhanSaahib) for more practical blue-team tools.

An offline tool that answers a question detection engineers ask constantly
and rarely have hard data for: **"if this technique were used against us
right now, would we actually see it?"**

It cross-references your Sigma detection rules against a simple inventory
of the telemetry you actually collect, and produces an
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) heatmap
layer plus a markdown report showing four states per technique:

| State | Meaning |
|---|---|
| **Detected & visible** | you have a rule *and* the telemetry it needs |
| **Detected but blind** | a rule exists, but the log source it needs isn't in your inventory -- false confidence, the rule will never fire |
| **Visible but undetected** | you collect telemetry ATT&CK associates with this technique, but no rule covers it -- a gap to write a rule for |
| **No coverage** | neither telemetry nor a rule |

## Quick start

Run the included Sigma rules and telemetry inventory through the full
analysis path:

```bash
git clone https://github.com/KhanSaahib/attackgap.git
cd attackgap
python -m pip install -e .
attackgap \
  --rules tests/fixtures/rules \
  --inventory tests/fixtures/inventory.json \
  --attack-data tests/fixtures/attack_sample.json \
  --layer-output coverage-layer.json \
  --report-output coverage-report.md
```

Open `coverage-report.md` for the findings or import `coverage-layer.json`
into ATT&CK Navigator.

## How it works

```mermaid
flowchart LR
    A[Sigma rules] --> D[Coverage scorer]
    B[Telemetry inventory] --> D
    C[ATT&CK bundle] --> D
    D --> E[Navigator layer]
    D --> F[Gap report]
    D --> G[CI gate]
```

## Why this exists

Having a Sigma rule for a technique feels like coverage. It isn't, if the
rule's `logsource` (`product`/`service`/`category`) doesn't match anything
you ingest -- a very common state after a SIEM migration, a decommissioned
log source, or a rule copied from a blog post written for a different
stack. `attackgap` makes that gap visible instead of discovering it during
an incident.

It's a companion to two of my other tools in
[`blue-forge`](https://github.com/KhanSaahib/blue-forge): `sigmajson` runs
detection, `honeycorrelate` tags incidents with ATT&CK after the fact --
`attackgap` scores your coverage *before* either of those matters.

## Install

Dependency-free (Python 3.10+ standard library only).

```bash
git clone https://github.com/KhanSaahib/attackgap.git
cd attackgap
python -m pip install -e ".[dev]"
python -m pytest -q   # optional: run the test suite
```

Or as a package:

```bash
attackgap --help
# Equivalent: python -m attackgap --help
```

## Usage

```bash
attackgap \
  --rules ./sigma-rules/ \
  --inventory ./inventory.json \
  --attack-data ./enterprise-attack.json \
  --layer-output ./coverage-layer.json \
  --report-output ./coverage-report.md
```

- `--rules` -- a directory of Sigma `.yml`/`.yaml` rule files (searched
  recursively). Only `title`, `id`, `status`, `logsource` and `tags` are
  read; the `detection` block is ignored, since attackgap scores coverage,
  it doesn't evaluate rules against logs. Rules marked `deprecated` or
  `unsupported` are excluded so retired content cannot inflate coverage.
- `--inventory` -- a JSON file describing what you actually collect (see
  below). Required.
- `--attack-data` -- optional, a local MITRE ATT&CK Enterprise STIX bundle
  JSON you download yourself from
  [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).
  Without it, attackgap can still classify every technique your rules
  reference as visible or blind; with it, it also finds "visible but
  undetected" and "no coverage" techniques across the *entire* ATT&CK
  matrix, and fills in technique names/tactics. Nothing from that dataset
  is bundled with this repo -- you point the tool at your own copy.
- `--layer-output` -- write an ATT&CK Navigator layer file. Open
  [the Navigator](https://mitre-attack.github.io/attack-navigator/) and use
  "Open Existing Layer" to load it as a heatmap.
- `--report-output` -- write a markdown gap report; without it, the report
  prints to stdout (`--format json` for a machine-readable version instead).

For CI, `--fail-on blind` exits `1` when a rule exists but its telemetry is
missing. `--fail-on actionable` also gates on visible-but-undetected
techniques, while `--fail-on any-gap` includes techniques with no coverage at
all. The default, `--fail-on never`, keeps reporting informational.

### Inventory format

A format this tool defines itself -- plain JSON, no external schema:

```json
{
  "sources": [
    {"product": "windows", "service": "sysmon",
     "categories": ["process_creation", "network_connection"]},
    {"product": "linux", "categories": ["auth"]},
    {"service": "cloudtrail", "categories": ["*"]}
  ],
  "data_sources": [
    "Process: Process Creation",
    "Command: Command Execution"
  ]
}
```

`sources` entries are matched against each rule's `logsource` block
(`product`/`service` must match exactly if the entry specifies them;
`category` must appear in `categories`, or `categories` can be `["*"]` for
"anything from this source"). `data_sources` is free text matched
(case-insensitive substring) against ATT&CK's `x_mitre_data_sources`
strings when `--attack-data` is supplied.

## How scoring works

A technique is `DETECTED_VISIBLE` if *any* rule referencing it has a
`logsource` that matches your inventory -- one working rule is enough, even
if other rules for the same technique are blind. It's `DETECTED_BLIND` only
if every rule for it is blind. `VISIBLE_UNDETECTED` and `NO_COVERAGE` only
apply to techniques with zero matching rules, and only get computed at all
when `--attack-data` is given (see `attackgap/scorer.py`).

## Project layout

```
attackgap/
  models.py         dataclasses + the four coverage states and their scores/colors
  sigma_reader.py    minimal, targeted Sigma metadata reader (not a full YAML parser)
  inventory.py       telemetry inventory format + logsource matching
  attack_data.py     optional MITRE ATT&CK STIX bundle reader
  scorer.py          the coverage-gap logic
  navigator.py       ATT&CK Navigator layer JSON writer
  report.py          markdown report renderer
  cli.py             argument parsing and wiring
tests/               pytest suite with synthetic fixtures for every coverage state
```

## Attributions

See [NOTICE.md](NOTICE.md) for every external format/idea this design
draws on and its license -- no third-party code is copied into this
repository.

## License

MIT, see [LICENSE](LICENSE).

## Community and project health

- [Contributing guide](CONTRIBUTING.md) — development setup and review expectations
- [Code of Conduct](CODE_OF_CONDUCT.md) — participation standards and enforcement
- [Security policy](SECURITY.md) — supported versions and private reporting
- [Support guide](SUPPORT.md) — how to ask for help safely
- [Changelog](CHANGELOG.md) — notable changes by release
