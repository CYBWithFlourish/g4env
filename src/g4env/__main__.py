"""Allow ``python -m g4env`` to behave exactly like the ``g4env`` script."""

from __future__ import annotations

from g4env.cli import main

if __name__ == "__main__":  # pragma: no cover - trivial delegation
    raise SystemExit(main())
