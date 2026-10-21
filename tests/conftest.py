"""Shared pytest fixtures."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from g4env.bench.tokens import STRIPE_KEY as FAKE_STRIPE_KEY
from g4env.scanning.loader import FileKind, SourceUnit


@pytest.fixture()
def sample_env(tmp_path: Path) -> Path:
    """Write a .env file that contains one obvious secret."""
    path = tmp_path / ".env"
    path.write_text(
        "\n".join(
            [
                "# demo configuration",
                "PORT=8000",
                "STRIPE_API_KEY=" + FAKE_STRIPE_KEY,
                "API_KEY=${STRIPE_SECRET_KEY}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def sample_tree(tmp_path: Path) -> Path:
    """Build a small project tree with several interesting files."""
    root = tmp_path / "project"
    (root / "config").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)

    (root / ".env").write_text(
        "STRIPE_API_KEY=" + FAKE_STRIPE_KEY + "\n",
        encoding="utf-8",
    )
    (root / ".env.example").write_text(
        "API_KEY=your-api-key-here\n",
        encoding="utf-8",
    )
    (root / "config" / "app.yaml").write_text(
        "database:\n  url: postgres://user:realpassword@db.internal:5432/app\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n      - env:\n          API_TOKEN: literal-token-value\n",
        encoding="utf-8",
    )
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "node_modules" / "left-pad" / "index.js").write_text(
        "const key = '" + FAKE_STRIPE_KEY + "';\n",
        encoding="utf-8",
    )
    return root


def make_unit(
    text: str,
    *,
    name: str = ".env",
    kind: FileKind = FileKind.ENV,
    template: bool = False,
) -> SourceUnit:
    """Build a :class:`SourceUnit` from a string."""
    return SourceUnit(
        path=Path(name),
        rel_path=name,
        kind=kind,
        text=text,
        lines=tuple(text.splitlines()),
        size=len(text),
        is_template=template,
    )


class _MockServer:
    """A tiny HTTP server used to fake an Ollama or Gemini endpoint.

    A handler may return a plain payload (answered with ``200``) or a
    ``(status, payload)`` pair so that error paths can be exercised.
    """

    def __init__(self, handler: Callable[[str, dict[str, Any]], Any]) -> None:
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.headers: list[dict[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _respond(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(raw.decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    payload = {}
                outer.requests.append((self.path, payload))
                outer.headers.append(
                    {key.lower(): value for key, value in self.headers.items()}
                )
                result = handler(self.path, payload)
                status = 200
                if isinstance(result, tuple):
                    status, result = result
                encoded = json.dumps(result).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            do_GET = _respond
            do_POST = _respond

            def log_message(self, *args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture()
def mock_server():
    """Yield a factory that starts a mock HTTP server."""
    servers: list[_MockServer] = []

    def factory(handler: Callable[[str, dict[str, Any]], Any]) -> _MockServer:
        server = _MockServer(handler)
        servers.append(server)
        return server

    yield factory
    for server in servers:
        server.close()
