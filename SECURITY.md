# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| `0.1.x` | Supported |
| Earlier versions | Not supported |

Only the latest patch release on the current minor line receives security
fixes. The `main` branch may contain unreleased changes.

## Reporting a vulnerability

Use the repository's **Security** tab to submit a private vulnerability
report. If private reporting is unavailable, open a minimal issue requesting a
private contact channel and do not include exploit details.

Include the affected version, a minimal reproduction, observed impact, and any
suggested remediation or embargo needs. The maintainer will acknowledge reports
on a best-effort basis, validate the impact, and coordinate disclosure before
publishing details.

## Scope

`attackgap` only reads local files and writes requested reports. Those reports
can reveal internal rule names and telemetry gaps; review them before sharing.
The tool is decision support, not proof that a control will detect a real
attack.
