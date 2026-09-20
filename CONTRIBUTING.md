# Contributing

Thanks for helping improve `attackgap`.

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
