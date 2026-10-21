# Using g4env in CI

g4env is designed to fail a build when a secret is committed.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, nothing met the failure threshold |
| 1 | Operational or analysis error |
| 2 | Usage error |
| 3 | Policy violation — a finding met or exceeded `--fail-on` |

---

## GitHub Actions

```yaml
name: secret-scan

on:
  push:
  pull_request:

jobs:
  g4env:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install g4env
        run: |
          python -m pip install --upgrade pip
          python -m pip install g4env

      - name: Audit the project
        run: g4env audit . --format json --fail-on high > g4env-report.json

      - name: Upload the report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: g4env-report
          path: g4env-report.json
```

`--format json` writes raw JSON to stdout, so the file is always schema
correct. The command exits with `3` when a finding meets the threshold, which
fails the step. Use `--fail-on none` if you only want the report.

To keep the report even when the step fails, use `continue-on-error: true` and
check the exit code yourself.

---

## GitLab CI

```yaml
secret-scan:
  stage: test
  image: python:3.12-slim
  script:
    - pip install --no-cache-dir g4env
    - g4env audit . --format json --fail-on high > g4env-report.json || true
    - |
      if [ $? -eq 3 ]; then
        echo "g4env found secrets" >&2
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - g4env-report.json
```

---

## Local pre-commit hook

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
set -euo pipefail

if ! command -v g4env >/dev/null 2>&1; then
  echo "g4env is not installed; skipping the secret scan" >&2
  exit 0
fi

g4env audit . --fail-on high --format text
```

Install it with:

```bash
chmod +x .git/hooks/pre-commit
```

---

## Validating a report

Every report is validated against schema 1.0 before it is written, but you can
re-check a stored report at any time:

```bash
g4env schema --validate g4env-report.json
```

```text
g4env-report.json matches report schema 1.0
```

---

## Choosing a threshold

| Threshold | Use it for |
| --- | --- |
| `--fail-on critical` | Advisory runs, you only want to block on private keys |
| `--fail-on high` (default) | Blocking CI runs |
| `--fail-on medium` | Strict repositories |
| `--fail-on low` | Very strict repositories |
| `--fail-on none` | Report only, never fail the build |
