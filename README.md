# g4env - Gemma 4 Environment Security

**Catch exposed secrets before they become security vulnerabilities.**

`g4env` is a local-first, terminal-native security auditing tool designed to help developers identify exposed credentials, hardcoded secrets, and insecure environment configurations before they become a problem.

It scans `.env` files, configuration files, CI/CD pipeline definitions, and codebases for potential security risks, including API keys, private keys, database credentials, weak passwords, and other sensitive values that should never be exposed or committed to version control.

By combining fast, deterministic rule-based detection with optional AI-powered contextual analysis through locally running Gemma models, `g4env` helps developers identify security issues while maintaining control over their sensitive configuration data.

Unlike tools that require cloud-based analysis by default, `g4env` is designed to work offline out of the box. Its default rule-based auditing engine makes no network requests, while its optional Ollama integration enables deeper analysis using models running on your own machine.

The project is currently under active development and is available for local testing and community feedback. It has not yet been published on PyPI, so the recommended way to try it is to clone the repository and run it locally. A public PyPI release is planned as the project matures, its capabilities improve, and it gains broader community reach.

---

## Why g4env?

Environment variables and configuration files are essential to modern software development, but they can also become a major source of security vulnerabilities.

A forgotten API key in a `.env` file, a private key committed to a repository, or a hardcoded credential inside a CI/CD pipeline can expose applications and infrastructure to unauthorized access.

`g4env` helps developers identify these risks early by making security auditing accessible directly from the terminal.

### How is this different from GitHub secret scanning?

They solve different problems, and the strongest setup uses both.

GitHub's secret scanning is a **repository gate for known provider credentials**. It ships a curated catalog of partner key formats - Stripe, Slack, AWS, GitHub tokens, and so on - and blocks a push when a blob matches one of them. That is genuinely valuable, but it is a needle detector for a fixed catalog, and it only looks at content that is on its way to GitHub.

`g4env` is a **security linter for configuration**, and it runs before anything leaves your machine:

- **It knows about your secrets, not just the providers'.** A password for your internal Postgres, a bearer token for your own API, or a shared credential with no recognizable format has no vendor signature. `g4env` catches those through name heuristics (`*_TOKEN`, `*_SECRET`, `*_PASSWORD`), entropy analysis, and optionally a local model that reads the surrounding context.
- **It understands configuration mistakes, not just credentials.** A real key pasted into `.env.example`, a weak password, a high-entropy value in an unclassified variable, a hardcoded `Authorization` header in application code, a literal secret in a CI workflow, a `.env` file that was never added to `.gitignore` - GitHub has no opinion on any of these. `g4env` does.
- **It scans what GitHub never sees.** Untracked files, Kubernetes manifests, Dockerfiles, local overlays, build output - anything in a directory, whether or not it is under version control.
- **It can run air-gapped.** Auditing proprietary code does not require uploading it anywhere. The default provider makes zero network requests.
- **It explains itself.** Every finding carries severity, confidence, evidence, impact, and a concrete fix, and the report is a versioned JSON schema you can diff, store, and gate CI on. GitHub tells you the push was blocked; `g4env` tells you what to change and in what order.
- **It redacts on the way out.** Secret values are masked in terminal output by default, so a screenshot, a CI log, or a bug report does not become a new leak.

The intended workflow is simple: run `g4env audit` locally and in CI to catch the problem at the source, and keep GitHub's protection as the backstop for anything that slips through or for history that already contains a leak.

### Key Features

**🔍 Secret and Credential Detection**

Detects potential security issues, including:

- Exposed API keys and access tokens.
- Embedded private keys.
- Hardcoded database credentials.
- Weak or guessable passwords.
- Sensitive values in example and template configuration files.
- Hardcoded credentials in authorization headers.
- Literal secrets inside CI/CD pipeline definitions.
- Environment files that may be unintentionally tracked by version control.
- High-entropy strings that could represent unclassified secrets.

Its detection rules recognize many common credential formats associated with services and platforms such as AWS, GitHub, GitLab, Google, OpenAI, Anthropic, Stripe, Slack, Cloudflare, Supabase, and others.

**🔒 Local-First and Privacy-Focused**

Privacy is a core design principle of `g4env`.

The default rule-based provider runs locally without making network requests. This allows developers to audit sensitive files without transmitting their contents to an external service.

For developers who want deeper analysis, the optional Ollama provider runs supported language models locally, keeping the analysis within their own environment.

A hosted Gemini provider is also available as an explicit opt-in option. When enabled, it sends redacted file content to the hosted API, and the tool communicates this network boundary to the user.

**🤖 AI-Powered Contextual Analysis**

Regular expressions are effective at identifying known credential patterns, but not every secret follows a predictable format.

With its optional Ollama integration, `g4env` can combine deterministic detection with local model-based analysis to identify additional contextual security concerns.

The tool also supports an optional hosted Gemini provider for users who choose remote analysis.

Both model-assisted providers run the deterministic rules first and then add contextual findings, helping combine predictable detection with more flexible analysis.

**🛡️ Automatic Secret Redaction**

Detected secret values are masked in terminal output and logs by default.

The tool also redacts sensitive values before sending content to a model provider, helping reduce the risk of exposing credentials during analysis.

Raw-value output can be explicitly requested when necessary, but it should be used with caution.

**⚙️ Built for Developers and CI/CD Workflows**

`g4env` is designed to fit into existing development and security workflows.

It supports structured JSON reports, readable terminal tables, and plain-text output. Its versioned report schema provides a consistent format for consuming and validating findings programmatically.

Configurable severity thresholds and predictable exit codes also make it possible to use the tool in automated workflows that need to fail when findings meet a specified severity.

**📊 Security Reports and Benchmarking**

Each audit produces findings containing information such as:

- Finding ID and severity.
- Confidence score.
- Description of the potential vulnerability.
- Evidence and relevant file location.
- Potential impact.
- Recommended remediation.
- Detection source, identifying whether the finding originated from a deterministic rule or a model.

Reports follow a versioned JSON schema and are validated before being written.

The project also includes a local benchmarking command and a labelled test dataset for evaluating detection quality across supported providers.

---

## How It Works

`g4env` combines deterministic security checks with optional contextual analysis.

1. **Provide a target:** Specify an individual configuration file or a directory to audit. If you omit the path, the current project directory is audited.
2. **Load and validate inputs:** The tool checks supported inputs and applies file-size, format, and binary-file safeguards.
3. **Run deterministic checks:** The rule engine searches for known secret patterns and common environment configuration mistakes.
4. **Perform optional contextual analysis:** If an AI provider is selected, the tool adds model-generated findings to the rule-based results.
5. **Redact sensitive values:** Secret values are masked in outputs, and sensitive content is redacted before model prompting.
6. **Generate a report:** Findings are returned as text, a terminal table, or schema-validated JSON.

Directory scans respect `.gitignore` and `.g4envignore` exclusions and skip common vendored dependencies, build outputs, and binary files.

---

## The two model modes

`g4env` always runs the deterministic rules first. On top of them you can add a model that reasons about context. There are exactly two ways to do that, and they differ in one important respect: **where the model runs**.

| | Mode A - local (Ollama) | Mode B - hosted (Gemini API) |
| --- | --- | --- |
| Flag | `--provider ollama` | `--provider gemini` |
| Model | `gemma2:2b` (the local default) | any model your key can reach, e.g. `gemini-3.8-flash` or `gemma-4-26b-a4b-it` |
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

Mode B (hosted) sends **redacted** content to the Gemini API and requires an API key from the environment:

```bash
export GEMINI_API_KEY="your-key"
g4env models --provider gemini    # list the models your key can reach
g4env audit . --provider gemini   # rules + Gemini reasoning
```

Google retires models for new API keys, so `g4env models --provider gemini` is the
authoritative list for your key. If the configured model is not available, g4env says so on
stderr, continues with a model that answers, and records the model it actually used in the
report.

Both modes are opt-in; `--provider rules` (the default) never touches the network. Full setup
instructions, the privacy contract and a step-by-step procedure for **testing the current code
against the Gemini API** live in [`docs/providers.md`](docs/providers.md).

---

## Available Commands

The CLI currently includes several commands for auditing and development workflows.

| Command              | Purpose                                                        |
| -------------------- | -------------------------------------------------------------- |
| `g4env audit [PATH]` | Audit a file or directory for potential security issues. `PATH` is optional and defaults to the current project directory. |
| `g4env version`      | Display the CLI version and report schema version.             |
| `g4env models`       | List available models and optionally warm up a selected model. |
| `g4env rules`        | List deterministic detection rules and their severity levels.  |
| `g4env schema`       | Display the report schema or validate a report against it.     |
| `g4env bench`        | Run the local detection-quality benchmark.                     |

Audits support `text`, `table`, and `json` output formats, with configurable providers and severity thresholds.

### `g4env audit [PATH]`

| Option | Values | Default | Description |
| --- | --- | --- | --- |
| `--format` | `json`, `table`, `text` | `text` | Output format (`json` writes raw JSON to stdout). |
| `--provider` | `rules`, `ollama`, `gemini` | `rules` | Audit execution backend. |
| `--model` | model name | `gemma2:2b` (Ollama) | Model tag (`ollama`) or model name (`gemini`). For the hosted provider the key decides which models exist: run `g4env models --provider gemini` to see them. |
| `--host` | URL | `http://127.0.0.1:11434` | Ollama server URL. |
| `--fail-on` | `low`, `medium`, `high`, `critical`, `none` | `high` | Exit with code 3 when a finding meets or exceeds this severity. |
| `--redact` | flag | `true` | Mask sensitive secret values in outputs. |
| `--no-redact` | flag | - | Show raw values. Use with care. |
| `--timeout` | seconds | `120` | Timeout for model providers. |

Directory scans honour `.gitignore` and `.g4envignore`. Add a `.g4envignore` file next to the audited project to exclude paths from the scan; it uses the same syntax as `.gitignore`:

```gitignore
# skip the test fixtures and the vendored configuration
fixtures/
*.example.yaml
```

### What the output shows

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

In JSON mode every finding carries the same information as machine-readable fields:
`id`, `severity`, `confidence`, `title`, `description`, `evidence[]` (`line`, `text`, `path`),
`impact`, `remediation` and `source`.

---

## Detection rules

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
indicates a credential. See [`docs/rules.md`](docs/rules.md) for a rule-by-rule reference with
examples of what is and is not reported.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (no findings met the failure threshold). |
| 1 | Operational or analysis error (invalid input, unavailable provider). |
| 2 | Usage error (invalid flag or argument). |
| 3 | Policy violation: a finding met or exceeded `--fail-on`. |

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
    "duration_ms": 0,
    "network_scope": "none",
    "components": ["rules"]
  }
}
```

The full schema lives in [`src/g4env/schema/report_v1.json`](src/g4env/schema/report_v1.json) and
can be printed with `g4env schema --format json`. Every report is validated against it before it
is written, so `--format json` output is always schema-correct.

---

## Current Project Status

`g4env` has an initial implementation of its core functionality, including:

- A Python package and command-line interface.
- Deterministic, offline-first secret detection.
- Optional local model integration through Ollama.
- An optional hosted Gemini provider.
- Secret redaction and input validation.
- Structured, schema-validated security reports.
- Automated tests, linting, type-checking, and benchmarking workflows.

**The project is currently available for local testing and feedback. It has not yet been released on PyPI.**

We are continuing to improve the tool, refine its detection capabilities, evaluate its performance, and build community awareness before making a public package release.

---

## Try It Locally

Since `g4env` is not yet published on PyPI, you can test the current implementation directly from its GitHub repository.

### 1. Clone the repository

```bash
git clone https://github.com/CYBWithFlourish/g4env.git
cd g4env
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install the project locally

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

This installs the project in editable mode, along with its development and testing dependencies.

### 4. Run your first audit

```bash
g4env version

# audit the whole current project
g4env audit

# or a single file
g4env audit ./.env
```

You can also generate a JSON report:

```bash
g4env audit . --format json
```

To explore the available detection rules:

```bash
g4env rules
```

### 5. See it work without any setup

The repository ships with a set of demo fixtures, so you can see every rule
fire without a model, an API key or a network connection:

```bash
g4env audit examples
```

```text
g4env 1.0.0  |  target: examples
provider: rules (offline)  |  model: -  |  schema: 1.0
files scanned: 10  |  duration: 9 ms
risk score: 100/100

17 finding(s): 1 critical, 11 high, 5 medium.

  [CRITICAL] env.private-key  keys/deploy_key.txt:5
    Private key embedded in configuration
    ...
```

The fixtures cover all nine rules - a leaked key, a connection string with a
password, a weak password, a high entropy blob, a template with a real value,
a tracked `.env`, a hardcoded authorization header, a secret in a CI pipeline
and a private key block. `examples/clean.env` is the counterpart that reports
nothing. See [`examples/README.md`](examples/README.md) for the full map.

For local AI-assisted analysis, install the optional Ollama integration, ensure Ollama is running, and pull a supported model:

```bash
python -m pip install -e ".[ollama]"
ollama pull gemma2:2b
g4env models --warm
g4env audit . --provider ollama
```

For hosted analysis, export a Gemini API key (it is never accepted as a command line flag) and opt in explicitly:

```bash
python -m pip install -e ".[gemini]"
export GEMINI_API_KEY="your-key"
g4env audit . --provider gemini
```

[`docs/providers.md`](docs/providers.md) documents both provider modes in full, including a
step-by-step procedure for testing the current code against the Gemini API.

### Development

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
| [`examples/README.md`](examples/README.md) | The demo fixtures and which rule each of them triggers. |

---

## Roadmap

Our goal is to make `g4env` a more reliable, accessible, and useful security tool for developers.

Current areas of focus include:

- Improving secret-detection accuracy and reducing false positives.
- Strengthening contextual analysis and model evaluation.
- Expanding test coverage and benchmarking.
- Refining the developer experience and documentation.
- Gathering community feedback and contributions.
- Preparing for a future PyPI release once the project is more mature.

The timing of the public package release will depend on development progress, testing, and readiness.

---

## Contributing

`g4env` is still evolving, and feedback from developers is valuable.

You can help by testing the current implementation locally, reporting reproducible bugs, suggesting improvements, contributing detection rules, or helping improve the documentation.

When reporting a security-related issue, never include live credentials, private keys, or other sensitive information.

---

## License

`g4env` is licensed under the GPL-3.0-or-later license. See [LICENSE](LICENSE).

---

**Built for developers who want to catch configuration security issues early, without giving up control over their sensitive data.**
