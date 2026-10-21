# Rule reference

Every rule is deterministic, runs offline and is documented here. Run
`g4env rules` to list them with their severities, or `g4env rules --format json`
for a machine readable version.

Severity weights (used for the risk score): `LOW 3`, `MEDIUM 7`, `HIGH 15`,
`CRITICAL 35`, capped at 100.

---

## `env.raw-secret` — HIGH

Unencrypted API key or token detected in plaintext.

Fires when

- the value matches a known vendor signature, or
- the variable name looks like a credential (`*_KEY`, `*_TOKEN`, `*_SECRET`,
  `*_PASSWORD`, …) and the value is a literal, not a placeholder or a
  reference.

Recognised vendor formats include AWS access key ids, GitHub, GitLab, Google
API keys, OpenAI, Anthropic, Stripe, Slack, SendGrid, Twilio, npm, PyPI,
Hugging Face, DigitalOcean, Notion, Cloudflare, Sentry, Azure storage account
keys, JWTs and generic `Authorization: Basic` credentials.

```dotenv
STRIPE_API_KEY=sk_live_<24-or-more-random-characters>   # reported
API_KEY=${STRIPE_SECRET_KEY}                             # ignored (reference)
API_KEY=your-api-key-here                                # ignored (placeholder)
```

A real credential inside a comment is still reported — comments do not make a
key safe.

---

## `env.private-key` — CRITICAL

RSA, SSH or EC private key material embedded in a configuration file.

```dotenv
DEPLOY_KEY=-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB
-----END OPENSSH PRIVATE KEY-----
```

---

## `env.db-credentials` — HIGH

A database connection string that embeds a username and a password.

```dotenv
DATABASE_URL=postgres://appuser:sup3rs3cret@db.internal:5432/production
```

```yaml
connection: "Server=db01;Database=app;User Id=appuser;Password=hunter2prod;"
```

A placeholder password (`password`, `changeme`, …) is not reported.

---

## `env.insecure-default` — MEDIUM

A template or example file ships a real secret value instead of a placeholder.

```dotenv
# .env.example
API_KEY=your-api-key-here     # fine
API_KEY=sk_live_<random>     # reported
```

---

## `env.high-entropy` — MEDIUM

A high entropy string assigned to a variable whose name says nothing about its
purpose. Unlabelled opaque values are frequently forgotten credentials.

```yaml
CONFIG_BLOB=k3J4h5G6f7D8s9A0b1C2d3E4f5G6h7J8   # reported
BUILD_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa       # ignored (low entropy)
```

---

## `env.weak-password` — MEDIUM

A password variable set to a weak, guessable value.

```dotenv
DB_PASSWORD=admin        # reported
DB_PASSWORD=${DB_PASS}   # ignored (reference)
```

---

## `env.hardcoded-auth-header` — HIGH

An `Authorization` or API key header that carries a literal credential instead
of a runtime reference.

```python
session.headers.update({"Authorization": "Bearer abc123DEF456ghi789JKL012"})
```

---

## `env.secret-in-ci` — HIGH

A CI/CD pipeline definition assigns a literal value to a sensitive key.

```yaml
jobs:
  deploy:
    steps:
      - env:
          NPM_TOKEN: npm_<36-random-characters>
```

Use the pipeline secret store instead.

---

## `env.tracked-env-file` — MEDIUM

A `.env` file exists that is not excluded from version control, so it is likely
to be committed and published.

```text
.env exists and is not excluded by .gitignore
```

This is a project level check and only runs for directory audits.

---

## Model findings

Findings produced by a model backend use the `ctx.` prefix and carry
`"source": "model"`. They are additions on top of the rules, never a
replacement:

| Prefix | Meaning |
| --- | --- |
| `env.*` | Deterministic rule, `"source": "rule"` |
| `ctx.*` | Contextual finding from a model, `"source": "model"` |

Model output is treated as untrusted input: it is parsed defensively, every
field is validated, and evidence that does not exist in the audited file is
dropped.

---

## Tuning

| Variable | Purpose | Default |
| --- | --- | --- |
| `G4ENV_MAX_FILE_BYTES` | Largest file that is read | 1 MiB |
| `.g4envignore` | Extra ignore rules, same syntax as `.gitignore` | — |
| `.gitignore` | Honoured automatically for directory audits | — |
