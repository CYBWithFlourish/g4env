# g4env - Gemma 4 Environment Security

**Terminal-native, local-first environment config and secret leak auditing.**

g4env is an offline CLI for auditing `.env` files, configuration schemas, CI/CD pipelines and
codebases for hardcoded credentials, sensitive keys and environment anti-patterns. It combines
high-speed, deterministic regex checks with local Gemma model reasoning via Ollama to spot both
known key formats and contextual leaks - keeping your sensitive configs strictly on your machine.

---

## Why g4env?

Configuration files and environment variables often contain sensitive API keys and secrets that
should never leave your machine or be exposed to hosted AI services. g4env keeps your audit
workflow local and secure:

- **Offline by default** - the default provider relies on deterministic regex rules and makes no
  network calls.
- **Gemma-powered** - use a locally installed Gemma model through Ollama for deep contextual and
  semantic analysis.
- **Automation-friendly** - structured JSON output validated against a versioned report schema
  with CI-safe exit codes.
- **Automatic redaction** - detected secrets are automatically masked in terminal outputs and
  logs.
- **Explicit network boundaries** - nothing leaves your machine during an audit. The optional
  hosted Gemini provider is opt-in and says so loudly.

---

## Status

The initial implementation includes:

- Python package, `g4env` console script, and CI setup.
- Versioned report schema (1.0) with a documented exit-code contract.
- `g4env audit [PATH]` supporting `json`, `table`, and `text` formats; `PATH` defaults to the
  current project directory.
- Deterministic regex rules for `.env` and configuration files (offline, zero-model default).
- A local Ollama provider for Gemma models, including model listing and a warm-up command.
- An optional hosted Gemini provider for teams that accept a remote boundary.
- Safe input loading with path, size, and binary checks plus automated secret redaction.
- Model quality and benchmark metrics are measured locally and evaluated against documented test
  sets.

---

## Install

```bash
git clone https://github.com/CYBWithFlourish/g4env.git
cd g4env
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"      # installs dev, test, and lint dependencies
```

The default rule-based provider needs no extra dependencies. To audit using a local Ollama model,
install with the `ollama` extra:

```bash
python -m pip install -e ".[ollama]"
```

To use the hosted Gemini provider, install with the `gemini` extra:

```bash
python -m pip install -e ".[gemini]"
```

Both providers are implemented on top of the standard library, so the extras are accelerators
rather than requirements - `g4env` works without them.

Model weights are never committed to this repository.

---

## Quick start

```bash
# Check CLI version and report schema version
g4env version

# Audit the whole current project with deterministic offline rules
g4env audit

# Audit an environment file
g4env audit ./.env

# Output script-safe JSON to stdout for CI/CD pipelines
g4env audit . --format json

# Render a readable table for a configuration file
g4env audit ./config.yaml --format table

# Audit with a local Gemma model via Ollama
ollama pull gemma2:2b
g4env models --warm
g4env audit ./.env --provider ollama

# Audit with the hosted Gemini API (redacted content leaves the machine)
export GEMINI_API_KEY="your-key"
g4env audit ./.env --provider gemini
```

---

## The two model modes

g4env always runs the deterministic rules first. On top of them you can add a model that reasons
about context. There are exactly two ways to do that, and they differ in one important respect:
**where the model runs**.

| | Mode A - local (Ollama) | Mode B - hosted (Gemini API) |
| --- | --- | --- |
| Flag | `--provider ollama` | `--provider gemini` |
| Default model | `gemma2:2b` | `gemini-2.5-flash` |
| Where the model runs | On your own machine (Ollama server) | Google's hosted API |
| Network access | localhost only | outbound to `generativelanguage.googleapis.com` |
| What leaves the machine | Nothing | Redacted file content |
| API key needed | No | Yes (`GEMINI_API_KEY`) |
| Extra install | `pip install -e ".[ollama]"` (optional) | `pip install -e ".[gemini]"` (optional) |
| Report metadata | `"offline": true`, `"network_scope": "localhost-only"` | `"offline": false`, `"network_scope": "remote"` |
| Best for | Air-gapped machines, strict privacy rules | Stronger contextual reasoning, no GPU needed |

Mode A (local) keeps everything on the machine:

```bash
ollama serve                      # start the local Ollama server
ollama pull gemma2:2b
g4env models --provider ollama    # list what is installed
g4env audit . --provider ollama   # rules + local Gemma reasoning
```

Mode B (hosted) sends **redacted** content to the Gemini API and requires an API key from the
environment:

```bash
export GEMINI_API_KEY="your-key"
g4env models --provider gemini    # check the key and the connection
g4env audit . --provider gemini   # rules + Gemini reasoning
```

Both modes are opt-in; `--provider rules` (the default) never touches the network. Full setup
instructions, the privacy contract and a step-by-step procedure for **testing the current code
against the Gemini API** live in [`docs/providers.md`](docs/providers.md).

---

## Commands

### `g4env version`

Prints the CLI version and report schema version:

```text
g4env 1.0.0 (report schema 1.0)
```

### `g4env audit [PATH]`

Audits a target file or directory and generates a security report. `PATH` is optional: when it is
omitted, g4env audits the **current project directory** (`.`), walking it recursively.

```bash
g4env audit            # audit the whole current project
g4env audit .env       # audit a single file
g4env audit ./config   # audit a directory
```

| Option | Values | Default | Description |
| --- | --- | --- | --- |
| `--format` | `json`, `table`, `text` | `text` | Output format (json writes raw JSON to stdout). |
| `--provider` | `rules`, `ollama`, `gemini` | `rules` | Audit execution backend. |
| `--model` | model name | `gemma2:2b` | Model tag (`ollama`) or model name (`gemini`). |
| `--host` | URL | `http://127.0.0.1:11434` | Ollama server URL. |
| `--fail-on` | `low`, `medium`, `high`, `critical`, `none` | `high` | Exit with code 3 when a finding meets or exceeds this severity. |
| `--redact` | flag | `true` | Mask sensitive secret values in outputs. |
| `--no-redact` | flag | - | Show raw values. Use with care. |
| `--timeout` | seconds | `120` | Timeout for model providers. |

`PATH` may be a single file or a directory. Directories are walked while skipping vendored
dependencies, build output, binary files and anything excluded by `.gitignore` / `.g4envignore`.

The `ollama` and `gemini` providers always run the deterministic rules first and then add
contextual findings on top. Every finding records its origin in the `source` field (`rule` or
`model`).

#### What the output shows

The `text` and `table` renderers report **where** each leak was found and **what to do about
it**: the file and line, the impact, and a fix. Findings are grouped into a remediation plan, and
a numbered list of next steps closes the report:

```text
g4env 1.0.0  |  target: .
provider: rules (offline)  |  model: -  |  schema: 1.0
files scanned: 5  |  duration: 5 ms
risk score: 82/100

6 finding(s): 5 high, 1 medium.

  [HIGH] env.raw-secret  .env:2
    Raw API token detected
    A plaintext Stripe key was found assigned to STRIPE_API_KEY.
    evidence  STRIPE_API_KEY=sk_live_****
    impact    Exposed credentials can lead to unauthorized service access.
    fix       Move secrets to a secure secret manager or environment store.

  [HIGH] env.db-credentials  .env:3
    Database credentials in plaintext
    evidence  DATABASE_URL=postgres://appuser:****@db.internal:5432/production
    fix       Store the connection string in a secret manager and inject it at runtime.

  ...

Remediation plan

  [HIGH] env.raw-secret  (2 occurrences)
    where    .env:2, config/app.yaml:3
    fix      Move secrets to a secure secret manager or environment store.

  [MEDIUM] env.tracked-env-file  (1 occurrence)
    where    .env:1
    fix      Add the file to .gitignore and rotate the exposed values.

Next steps
  1. Rotate every credential that is stored in plaintext; assume it has already leaked through version control history.
  2. Move the values into a secret manager or your platform's encrypted environment store and reference them with a variable.
  3. Add the .env files to .gitignore, remove them from the index and purge them from the git history.
  4. Re-run `g4env audit .` to confirm that the remediation worked.
```

The `table` format prints the same findings as a sortable-looking overview followed by the
per-finding details:

```text
SEVERITY  RULE                       CONF  LOCATION                    TITLE
────────  ─────────────────────────  ────  ──────────────────────────  ───────────────────────
HIGH      env.raw-secret             0.95  .env:2                      Raw API token detected
HIGH      env.db-credentials         0.90  .env:3                      Database credentials in plaintext
MEDIUM    env.tracked-env-file       0.70  .env:1                      Environment file is not excluded from version control
```

In JSON mode every finding carries the same information as machine-readable fields:
`id`, `severity`, `confidence`, `title`, `description`, `evidence[]` (`line`, `text`, `path`),
`impact`, `remediation` and `source`.

### `g4env models`

Lists the models available to a provider.

| Option | Values | Default | Description |
| --- | --- | --- | --- |
| `--provider` | `ollama`, `gemini` | `ollama` | Which backend to query. |
| `--host` | URL | `http://127.0.0.1:11434` | Ollama server URL. |
| `--format` | `table`, `json` | `table` | Output format. |
| `--warm` | flag | - | Preload the selected model into memory. |
| `--model` | model name | provider default | Model to warm up. |

### `g4env rules`

Lists the deterministic rules with their severity and description.

| Option | Values | Default | Description |
| --- | --- | --- | --- |
| `--format` | `table`, `json` | `table` | Output format. |

### `g4env schema`

Shows the versioned report schema, or validates an existing report against it.

| Option | Values | Default | Description |
| --- | --- | --- | --- |
| `--format` | `json`, `text` | `text` | Output format. |
| `--validate` | path | - | Validate a report file against the schema. |

### `g4env bench`

Runs the local quality benchmark against the documented test set in
`src/g4env/bench/dataset.json`.

| Option | Values | Default | Description |
| --- | --- | --- | --- |
| `--format` | `json`, `table`, `text` | `text` | Output format. |
| `--provider` | `rules`, `ollama`, `gemini` | `rules` | Backend to evaluate. |
| `--model` | model name | provider default | Model tag or name. |
| `--host` | URL | `http://127.0.0.1:11434` | Ollama server URL. |

---

## Deterministic rules

Deterministic checks run instantly without model dependencies or network access:

| Rule ID | Severity | Description |
| --- | --- | --- |
| `env.raw-secret` | HIGH | Unencrypted API key or token detected in plaintext. |
| `env.private-key` | CRITICAL | RSA, SSH, or EC private key embedded in configuration. |
| `env.db-credentials` | HIGH | Plaintext database connection string containing username and password. |
| `env.insecure-default` | MEDIUM | Sensitive key in template/example file has a real secret value instead of a placeholder. |
| `env.high-entropy` | MEDIUM | High-entropy string assigned to an unclassified variable. |
| `env.weak-password` | MEDIUM | Password variable set to a weak, guessable value. |
| `env.hardcoded-auth-header` | HIGH | Authorization or API key header carrying a literal credential. |
| `env.secret-in-ci` | HIGH | Literal secret assigned inside a CI/CD pipeline definition. |
| `env.tracked-env-file` | MEDIUM | `.env` file present that is not excluded from version control. |

`env.raw-secret` recognises a wide range of vendor formats (AWS, GitHub, GitLab, Google, OpenAI,
Anthropic, Stripe, Slack, SendGrid, Twilio, npm, PyPI, Hugging Face, DigitalOcean, Notion, Cloudflare,
Sentry, Azure, Supabase/JWT, and more) as well as secret-shaped assignments whose variable name
indicates a credential.

---

## Report format

Reports follow schema version 1.0:

```json
{
  "schema_version": "1.0",
  "target": ".env",
  "risk_score": 15,
  "summary": "1 finding(s): 1 high.",
  "findings": [
    {
      "id": "env.raw-secret",
      "severity": "HIGH",
      "confidence": 0.95,
      "title": "Raw API token detected",
      "description": "A plaintext API secret was found assigned to STRIPE_API_KEY.",
      "evidence": [{ "line": 1, "text": "STRIPE_API_KEY=sk_live_****", "path": null }],
      "impact": "Exposed credentials can lead to unauthorized service access.",
      "remediation": "Move secrets to a secure secret manager or environment store.",
      "source": "rule"
    }
  ],
  "metadata": {
    "tool_version": "1.0.0",
    "provider": "rules",
    "offline": true,
    "model": null,
    "files_scanned": 1,
    "duration_ms": 3,
    "network_scope": "none",
    "components": ["rules"]
  }
}
```

The full schema lives in [`src/g4env/schema/report_v1.json`](src/g4env/schema/report_v1.json) and
can be printed with `g4env schema --format json`. Every report is validated against it before it
is written, so `--format json` output is always schema-correct.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (no findings met the failure threshold). |
| 1 | Operational or analysis error (invalid input, unavailable provider). |
| 2 | Usage error (invalid flag or argument). |
| 3 | Policy violation: a finding met or exceeded `--fail-on`. |

---

## Privacy & security boundaries

- Audit inputs remain local and offline by default.
- Files are validated for size and format constraints.
- Detected secrets are redacted prior to model prompting and display.
- Model outputs are treated as untrusted data and validated against strict schemas.

### Provider boundaries

| Provider | Network | What leaves the machine |
| --- | --- | --- |
| `rules` | none | Nothing. The default provider is fully offline. |
| `ollama` | localhost only | Nothing. The model runs on your machine. |
| `gemini` | remote | Redacted file content, sent to the hosted Gemini API. |

The Gemini provider is the only backend that transmits data off the machine. It is opt-in
(`--provider gemini`), it prints a notice on stderr, and the resulting report records
`"offline": false` and `"network_scope": "remote"` so downstream consumers can tell. Secrets are
still redacted before transmission.

The Gemini API key is read from the `GEMINI_API_KEY`, `GOOGLE_API_KEY` or `G4ENV_GEMINI_API_KEY`
environment variable only. It is deliberately *not* accepted as a command line flag, so it never
ends up in shell history or a process listing.

g4env is an audit assistant and does not replace comprehensive security reviews or secret
management best practices.

---

## Development

```bash
python -m pip install -e ".[dev]"
pytest                      # test suite
ruff check .                # lint
mypy                        # type check
g4env bench                 # rule quality against the labelled test set
```

### Documentation

| Document | Contents |
| --- | --- |
| [`docs/providers.md`](docs/providers.md) | The two model modes, Ollama and Gemini setup, the privacy contract, and how to test the current code against the Gemini API. |
| [`docs/rules.md`](docs/rules.md) | Every deterministic rule with examples of what is and is not reported. |
| [`docs/ci.md`](docs/ci.md) | Wiring g4env into GitHub Actions, GitLab CI and pre-commit, with exit-code thresholds. |

---

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
