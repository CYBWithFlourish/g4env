# Demo fixtures

These files exist so that you can see what `g4env` reports without setting up
a model, a network connection or an API key. Every credential in them is
fabricated.

```bash
# the whole set: 17 findings across all nine rules
g4env audit examples

# a single file
g4env audit examples/app.env

# machine readable
g4env audit examples --format json

# a clean file reports nothing and exits with 0
g4env audit examples/clean.env
```

The set is excluded from the repository's own self-scan through
`.g4envignore`, so `g4env audit .` inside this repository still reports
nothing. The ignore file is read from the directory you audit, which is why
`g4env audit examples` still sees every fixture.

## What each file demonstrates

| File | Rule | What it shows |
| --- | --- | --- |
| `app.env` | `env.raw-secret` | A secret shaped name with an opaque literal value. No vendor prefix, so no provider signature is needed to find it. |
| `app.env` | `env.db-credentials` | A connection string with a username and a password. |
| `app.env` | `env.weak-password` | A guessable password. |
| `opaque.env` | `env.high-entropy` | An opaque value in a variable whose name gives no clue. |
| `.env.example` | `env.insecure-default` | A template that still carries a real looking value. |
| `.env` | `env.tracked-env-file` | An environment file that is not excluded from version control. |
| `config/app.yaml` | `env.db-credentials`, `env.raw-secret` | The same problems in YAML. |
| `config/settings.json` | `env.raw-secret` | The same problem in JSON. |
| `.github/workflows/deploy.yml` | `env.secret-in-ci` | A literal credential inside a pipeline definition. |
| `source/client.py` | `env.hardcoded-auth-header` | An `Authorization` header with a literal token. |
| `keys/deploy_key.txt` | `env.private-key` | A private key block, the only CRITICAL finding. |
| `clean.env` | - | Nothing. A clean file, a zero exit code. |

## A note on the values

The credentials in these files deliberately carry **no provider prefix**. A
value such as `sk_live_...` or `ghp_...` has a known shape, and provider
secret scanners (including the one GitHub runs on every push) block commits
that contain one - even when it is only a documentation example.

The values here are shaped like secrets without impersonating a real
provider, which is also the class of leak that a provider-aware scanner
cannot see.

The provider specific formats are covered by the evaluation set instead:

```bash
g4env bench
```

That command runs the labelled dataset, which does contain AWS, GitHub,
Google, OpenAI, Anthropic, Stripe, Slack, SendGrid, npm, DigitalOcean and
JWT shaped values. They live in `src/g4env/bench/` and are assembled from
fragments at load time so that the repository stays pushable.
