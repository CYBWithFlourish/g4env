"""The ``g4env`` command line interface.

Exit code contract:

``0``
    Success, no finding met the failure threshold.
``1``
    Operational or analysis error (invalid input, unavailable provider).
``2``
    Usage error (invalid flag or argument).
``3``
    Policy violation: a finding met or exceeded ``--fail-on``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from g4env import __version__
from g4env.audit import AuditOptions, run_audit
from g4env.errors import G4EnvError, UsageError
from g4env.models import SCHEMA_VERSION, SEVERITY_ORDER, Threshold
from g4env.providers import PROVIDER_NAMES, create_provider
from g4env.report.render import render_json, render_table, render_text
from g4env.rules.builtin import get_rules
from g4env.schema import load_schema

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_POLICY = 3

_FORMATS = ("json", "table", "text")


def _human_size(size: int | None) -> str:
    if not size:
        return "-"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024
    return f"{value:.1f} TB"  # pragma: no cover - unreachable


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="g4env",
        description=(
            "Audit environment files, configuration and CI/CD pipelines for "
            "hardcoded credentials and environment anti-patterns."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"g4env {__version__} (report schema {SCHEMA_VERSION})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser("version", help="print version information")
    version_parser.set_defaults(handler=_handle_version)

    audit_parser = subparsers.add_parser(
        "audit",
        help="audit a file or directory (defaults to the current directory)",
    )
    audit_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="file or directory to audit; defaults to the current directory",
    )
    audit_parser.add_argument(
        "--format",
        choices=_FORMATS,
        default="text",
        help="output format (json writes raw JSON to stdout)",
    )
    audit_parser.add_argument(
        "--provider",
        choices=PROVIDER_NAMES,
        default="rules",
        help="audit execution backend",
    )
    audit_parser.add_argument(
        "--model",
        default=None,
        help="model tag used by the ollama and gemini providers",
    )
    audit_parser.add_argument(
        "--host",
        default=None,
        help="Ollama server URL",
    )
    audit_parser.add_argument(
        "--fail-on",
        choices=(*(level.lower() for level in SEVERITY_ORDER), "none"),
        default="high",
        help="exit with code 3 when a finding meets or exceeds this severity",
    )
    audit_parser.add_argument(
        "--redact",
        dest="redact",
        action="store_true",
        default=True,
        help="mask sensitive secret values in outputs (default)",
    )
    audit_parser.add_argument(
        "--no-redact",
        dest="redact",
        action="store_false",
        help="show raw secret values in outputs",
    )
    audit_parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="timeout in seconds for model providers",
    )
    audit_parser.set_defaults(handler=_handle_audit)

    models_parser = subparsers.add_parser("models", help="list models available to a provider")
    models_parser.add_argument(
        "--host",
        default=None,
        help="Ollama server URL",
    )
    models_parser.add_argument(
        "--provider",
        choices=("ollama", "gemini"),
        default="ollama",
        help="which backend to query",
    )
    models_parser.add_argument(
        "--model",
        default=None,
        help="model tag to warm up with --warm",
    )
    models_parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format",
    )
    models_parser.add_argument(
        "--warm",
        action="store_true",
        help="preload the selected model into memory",
    )
    models_parser.set_defaults(handler=_handle_models)

    rules_parser = subparsers.add_parser("rules", help="list the deterministic rules")
    rules_parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format",
    )
    rules_parser.set_defaults(handler=_handle_rules)

    schema_parser = subparsers.add_parser("schema", help="show or validate the report schema")
    schema_parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="output format",
    )
    schema_parser.add_argument(
        "--validate",
        metavar="REPORT",
        default=None,
        help="validate a report file against the schema",
    )
    schema_parser.set_defaults(handler=_handle_schema)

    bench_parser = subparsers.add_parser(
        "bench",
        help="run the local quality benchmark against the documented test set",
    )
    bench_parser.add_argument(
        "--format",
        choices=_FORMATS,
        default="text",
        help="output format",
    )
    bench_parser.add_argument(
        "--provider",
        choices=PROVIDER_NAMES,
        default="rules",
        help="backend to evaluate",
    )
    bench_parser.add_argument(
        "--model",
        default=None,
        help="model tag used by the ollama and gemini providers",
    )
    bench_parser.add_argument(
        "--host",
        default=None,
        help="Ollama server URL",
    )
    bench_parser.set_defaults(handler=_handle_bench)

    return parser


def _handle_version(args: argparse.Namespace) -> int:
    print(f"g4env {__version__} (report schema {SCHEMA_VERSION})")
    return EXIT_OK


def _handle_audit(args: argparse.Namespace) -> int:
    threshold = Threshold.parse(args.fail_on)
    provider = create_provider(
        args.provider,
        model=args.model,
        host=args.host,
        timeout=args.timeout,
    )
    if not provider.offline:
        scope = "the hosted Gemini API" if provider.name == "gemini" else "the local Ollama server"
        print(
            f"g4env: notice: --provider {provider.name} sends redacted file content to"
            f" {scope}; content leaves this process.",
            file=sys.stderr,
        )

    options = AuditOptions(
        target=Path(args.path),
        provider=provider,
        fail_on=threshold,
        redact=args.redact,
    )
    result = run_audit(options)
    for warning in result.warnings:
        print(f"g4env: warning: {warning}", file=sys.stderr)

    if args.format == "json":
        sys.stdout.write(render_json(result.report) + "\n")
    elif args.format == "table":
        sys.stdout.write(render_table(result.report))
    else:
        sys.stdout.write(render_text(result.report))

    for finding in result.report.findings:
        if threshold.triggered(finding.severity):
            return EXIT_POLICY
    return EXIT_OK


def _handle_models(args: argparse.Namespace) -> int:
    provider = create_provider(
        args.provider,
        model=args.model,
        host=args.host,
    )
    if args.warm:
        warm = getattr(provider, "warm", None)
        if callable(warm):
            warm()
            print(
                f"g4env: warmed up {provider.model} on {getattr(provider, 'host', 'the remote API')}",
                file=sys.stderr,
            )
        else:
            print("g4env: warning: --warm is not supported by this provider", file=sys.stderr)

    models = provider.list_models()
    if args.format == "json":
        payload = {
            "provider": provider.name,
            "model": provider.model,
            "models": [model.to_dict() for model in models],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return EXIT_OK

    headers = ("MODEL", "SIZE", "MODIFIED", "DETAILS")
    rows = [
        (model.name, _human_size(model.size), model.modified_at or "-", model.details or "-")
        for model in models
    ]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def format_row(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    sys.stdout.write(format_row(headers) + "\n")
    sys.stdout.write("  ".join("\u2500" * width for width in widths) + "\n")
    for row in rows:
        sys.stdout.write(format_row(row) + "\n")
    if not rows:
        sys.stdout.write("no models found\n")
    return EXIT_OK


def _handle_rules(args: argparse.Namespace) -> int:
    rules = get_rules()
    if args.format == "json":
        payload = [
            {
                "id": rule.id,
                "severity": rule.severity.value,
                "confidence": rule.confidence,
                "title": rule.title,
                "description": rule.description,
                "impact": rule.impact,
                "remediation": rule.remediation,
            }
            for rule in rules
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return EXIT_OK

    headers = ("RULE ID", "SEVERITY", "CONF", "DESCRIPTION")
    rows = [
        (rule.id, rule.severity.value, f"{rule.confidence:.2f}", rule.description)
        for rule in rules
    ]
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def format_row(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    sys.stdout.write(format_row(headers) + "\n")
    sys.stdout.write("  ".join("\u2500" * width for width in widths) + "\n")
    for row in rows:
        sys.stdout.write(format_row(row) + "\n")
    return EXIT_OK


def _handle_schema(args: argparse.Namespace) -> int:
    schema = load_schema(SCHEMA_VERSION)
    if args.validate:
        path = Path(args.validate)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise UsageError(f"cannot read {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise UsageError(f"{path} is not valid JSON: {exc}") from exc
        errors = _validate(payload)
        if errors:
            print(f"g4env: {path} does not match schema {SCHEMA_VERSION}:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            return EXIT_ERROR
        print(f"{path} matches report schema {SCHEMA_VERSION}")
        return EXIT_OK

    if args.format == "json":
        sys.stdout.write(json.dumps(schema, indent=2) + "\n")
    else:
        sys.stdout.write(
            f"report schema {SCHEMA_VERSION}\n"
            f"  title:     {schema.get('title', '-')}\n"
            f"  required:  {', '.join(schema.get('required', []))}\n"
            f"  path:      {schema.get('$id', '-')}\n"
        )
    return EXIT_OK


def _validate(payload: object) -> list[str]:
    from g4env.schema import validate

    return validate(payload, load_schema(SCHEMA_VERSION))


def _handle_bench(args: argparse.Namespace) -> int:
    from g4env.bench.runner import format_bench_json, format_bench_text, run_benchmark

    provider = create_provider(args.provider, model=args.model, host=args.host)
    result = run_benchmark(provider)
    if args.format == "json":
        sys.stdout.write(format_bench_json(result) + "\n")
    else:
        sys.stdout.write(format_bench_text(result))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``g4env`` console script."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:  # pragma: no cover - argparse enforces a command
        parser.print_help()
        return EXIT_USAGE
    try:
        return handler(args)
    except UsageError as exc:
        print(f"g4env: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except G4EnvError as exc:
        print(f"g4env: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - piping into head and friends
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover - interactive use
        print("g4env: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
