# Providers

g4env ships with three backends. Two of them add model reasoning on top of the
deterministic rules.

| Provider | Model | Network | Use it when |
| --- | --- | --- | --- |
| `rules` | none | none | You want the fast, fully offline check. This is the default. |
| `ollama` | local Gemma | localhost only | You run inference locally and want contextual findings. |
| `gemini` | hosted Gemini | remote | You cannot run local inference but have an API key. |

The `ollama` and `gemini` providers **always run the deterministic rules
first** and then add model findings on top. A finding produced by a model is
marked with `"source": "model"`; everything else is `"source": "rule"`. The
model never replaces a rule.

---

## Mode 1 — local inference with Ollama

Nothing leaves your machine. The Ollama server runs on `127.0.0.1` by default.

### Setup

```bash
# 1. Install Ollama (https://ollama.com/download)
ollama --version

# 2. Pull a model
ollama pull gemma2:2b

# 3. Confirm the server is reachable
g4env models
```

### Use it

```bash
# List the models the server exposes
g4env models
g4env models --format json

# Preload the model so the first audit is not slow
g4env models --warm --model gemma2:2b

# Audit the current project with rules + local Gemma
g4env audit . --provider ollama
g4env audit . --provider ollama --model gemma2:2b

# Point at a different server
g4env audit . --provider ollama --host http://127.0.0.1:11434
```

### Notes

- The provider speaks the Ollama HTTP API with the standard library, so the
  `ollama` extra is optional. Install `pip install -e ".[ollama]"` if you
  prefer the official client.
- The server is contacted on `localhost` only. If you point `--host` at a
  remote address, g4env will happily use it — that is your call, but the
  report will still record `localhost-only` as the network scope because the
  provider itself does not enforce the boundary.

---

## Mode 2 — hosted Gemini API

This is the mode for users who cannot run local inference. It requires an API
key and it is the **only** mode that sends data off the machine.

### Setup

```bash
# 1. Get an API key from https://aistudio.google.com/apikey

# 2. Export it (never pass it as a flag, see below)
export GEMINI_API_KEY="your-key-here"

# 3. Optional: install the official SDK
pip install -e ".[gemini]"

# 4. Check that the key works
g4env models --provider gemini
```

### Use it

```bash
# Audit the current project with rules + Gemini
g4env audit . --provider gemini

# Use a different model
g4env audit . --provider gemini --model gemini-2.5-flash

# Machine readable output
g4env audit . --provider gemini --format json
```

### What happens to your data

- The file content is **redacted before it is sent**. Detected secrets are
  replaced with `****`, so a leaked API key is not transmitted.
- g4env prints a notice on stderr before the first request:

  ```text
  g4env: notice: --provider gemini sends redacted file content to the hosted
  Gemini API; content leaves this process.
  ```

- The report records the boundary so downstream consumers can act on it:

  ```json
  "metadata": {
    "provider": "gemini",
    "offline": false,
    "network_scope": "remote",
    "components": ["rules", "gemini"]
  }
  ```

### Where the API key comes from

The key is read from the environment, in this order:

1. `GEMINI_API_KEY`
2. `GOOGLE_API_KEY`
3. `G4ENV_GEMINI_API_KEY`

There is deliberately **no `--api-key` flag**. A flag would end up in shell
history, in `ps` output and in CI logs.

---

## Testing the current code against the Gemini API

### 1. Check the key and the connection

```bash
export GEMINI_API_KEY="your-key-here"
g4env models --provider gemini
```

Expected output:

```text
MODEL                   SIZE  MODIFIED  DETAILS
──────────────────────── ───── ───────── ─────────
gemini-2.5-flash        -     -         Flash
```

If you see `g4env: error: the Gemini API returned HTTP 400 ...`, the key is
wrong. If you see `cannot reach the Gemini API`, the request was blocked by a
firewall or proxy.

### 2. Run the benchmark against the labelled test set

```bash
g4env bench --provider gemini --format json
```

The benchmark runs the labelled cases in `src/g4env/bench/dataset.json`
through the provider and reports precision, recall and F1. A model provider
should score well above the `rules` baseline on the contextual cases.

### 3. Audit a known file and compare the findings

```bash
mkdir -p /tmp/g4env-demo && cd /tmp/g4env-demo
# The bundled fake credential keeps the demo free of realistic looking tokens.
python - <<'PY'
from g4env.bench.tokens import STRIPE_KEY

with open(".env", "w", encoding="utf-8") as handle:
    handle.write(f"STRIPE_API_KEY={STRIPE_KEY}\n")
    handle.write("DATABASE_URL=postgres://appuser:sup3rs3cret@db.internal:5432/production\n")
PY

# Rules only (offline, instant)
g4env audit .env --provider rules

# Rules + Gemini (sends the redacted file content)
g4env audit .env --provider gemini
```

The rules run must report `env.raw-secret` and `env.db-credentials`. The Gemini
run reports the same findings **plus** any contextual findings the model
produced. The `source` field tells you which is which:

```bash
g4env audit .env --provider gemini --format json \
  | python -c "import json,sys; [print(f['source'], f['id']) for f in json.load(sys.stdin)['findings']]"
```

### 4. Verify that no secret leaves the machine

g4env redacts before it sends. You can check this without a real API key by
pointing the provider at a local mock server and inspecting the payload:

```bash
python - <<'PY'
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

captured = {}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        captured["body"] = self.rfile.read(length).decode()
        body = json.dumps({"candidates": [{"content": {"parts": [{"text": '{"findings": []}'}]}}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()

from g4env.providers.gemini import GeminiProvider, GeminiRestTransport
from g4env.bench.tokens import STRIPE_KEY
from g4env.scanning.loader import FileKind, SourceUnit

transport = GeminiRestTransport(api_key="test", base_url=f"http://127.0.0.1:{server.server_address[1]}/v1beta")
provider = GeminiProvider(api_key="test", transport=transport)
unit = SourceUnit(path=None, rel_path=".env", kind=FileKind.ENV,
                  text=f"STRIPE_API_KEY={STRIPE_KEY}\n",
                  lines=(f"STRIPE_API_KEY={STRIPE_KEY}",),
                  size=64, is_template=False)
provider.analyze_unit(unit)

print("secret leaked to the API:", STRIPE_KEY in captured["body"])
server.shutdown()
PY
```

Expected output:

```text
secret leaked to the API: False
```

### 5. Run the automated tests

The test-suite never touches the network. It starts a local mock server and
asserts the request payload, the API key header, the redaction and the error
handling:

```bash
pytest tests/test_providers.py -v
```

---

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no Gemini API key found` | The key is not exported | `export GEMINI_API_KEY=...` |
| `the Gemini API returned HTTP 400` | Invalid key | Create a new key in AI Studio |
| `the Gemini API returned HTTP 429` | Rate limit or quota | Wait, or use `--provider rules` |
| `the Gemini API blocked the request` | Safety filter | The content tripped the filter; the file is not sent again |
| `cannot reach the Gemini API` | Proxy or firewall | Check `HTTPS_PROXY` and outbound access |
| `the google-genai SDK is not installed` | Optional dependency missing | `pip install -e ".[gemini]"` or ignore — the REST fallback works |
| `cannot reach the Ollama server` | Ollama is not running | `ollama serve` |
| Model answers with prose | The model ignored the JSON mode | Lower the temperature is already done; try a larger model |
