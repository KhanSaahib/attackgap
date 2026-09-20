# Notice and attributions

`attackgap` is original code written for this repository. No third-party
source code was copied into this project. The items below are the external
references that informed its design or file formats; each is credited even
though nothing was reused verbatim.

## Data formats consulted (public specs, no code copied)

- **Sigma rule format** — https://github.com/SigmaHQ/sigma — the Sigma
  specification is released under the Detection Rule License (DRL 1.1) /
  the SigmaHQ rule repository content under DRL, but the *format itself*
  (YAML fields `logsource`, `tags`, `detection`) is public, documented
  schema. `attackgap/sigma_reader.py` implements its own minimal YAML field
  reader against this documented schema; no Sigma project code (pySigma,
  sigma-cli) was copied or vendored.
- **MITRE ATT&CK® STIX data** — https://github.com/mitre-attack/attack-stix-data
  — MITRE ATT&CK content, terms at https://attack.mitre.org/resources/legal-and-branding/terms-of-use/.
  `attackgap/attack_data.py` optionally reads a user-supplied local STIX
  bundle (downloaded separately by the user from MITRE's own repository) to
  resolve technique names/tactics/data sources. **No ATT&CK data is bundled,
  vendored, or redistributed in this repository** — the tool only parses a
  file the user already has locally, which avoids any redistribution
  question entirely.
- **MITRE ATT&CK Navigator layer format** — https://github.com/mitre-attack/attack-navigator
  (Apache License 2.0) — `attackgap/navigator.py` writes JSON in the
  documented Navigator layer-file shape (`techniques[].techniqueID/score/color`,
  `gradient`, `legendItems`, `versions`) so output can be dropped into the
  real Navigator UI. This uses the *documented file format* only; no
  Navigator source code was copied.

## Conceptual prior art (ideas only, no code reused)

- **DeTT&CT** — https://github.com/rabobank-cdc/DeTTECT — GNU GPL-3.0.
  Pioneered the idea of scoring ATT&CK technique coverage by comparing
  detection rules against data-source visibility to find "false confidence"
  gaps. `attackgap` independently reimplements this general idea against
  Sigma rules with its own scoring model and code; no DeTT&CT source was
  read or copied, so no GPL obligations attach here — this is an
  attribution of the idea only.
- **sigmajson** and **honeycorrelate** (this author's own tools in
  `KhanSaahib/blue-forge`, MIT) — prior work on Sigma-driven detection and
  ATT&CK-tagged incident correlation; `attackgap` is a natural companion
  that scores coverage *before* an incident rather than tagging one after.
