# Contributing

Thanks for helping improve `attackgap`.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
For usage questions, read [SUPPORT.md](SUPPORT.md). Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

Keep the runtime dependency-free and offline. Changes to Sigma metadata
parsing, inventory matching, scoring, or Navigator output should include a
small synthetic fixture and focused tests. Do not add third-party ATT&CK or
Sigma rule data to the repository.

## Pull requests

- Keep each pull request focused and explain the user-facing impact.
- Add or update tests for behavior changes and boundary conditions.
- Update the README and `[Unreleased]` changelog for user-visible changes.
- Run `python -m pytest -q` and `python -m build` before requesting review.
- Do not include proprietary rules, telemetry inventories, or ATT&CK datasets.

Maintainers may request changes when evidence is incomplete, behavior is not
deterministic, or a contribution expands the project's stated scope.
