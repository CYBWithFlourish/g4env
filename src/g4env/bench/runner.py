"""Local quality benchmark for the deterministic and model providers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from g4env.bench.dataset import BenchCase, load_cases
from g4env.providers.base import Provider
from g4env.scanning.discovery import classify
from g4env.scanning.loader import FileKind, SourceUnit

__all__ = [
    "BenchResult",
    "CaseOutcome",
    "format_bench_json",
    "format_bench_text",
    "run_benchmark",
]


@dataclass(frozen=True)
class CaseOutcome:
    """The result of running one labelled case through a provider."""

    case_id: str
    rationale: str
    expected: tuple[str, ...]
    found: tuple[str, ...]
    matched: tuple[str, ...]
    missed: tuple[str, ...]
    spurious: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """Return ``True`` when the provider produced exactly the expected ids."""
        return not self.missed and not self.spurious


@dataclass(frozen=True)
class BenchResult:
    """Aggregated benchmark results."""

    provider: str
    model: str | None
    outcomes: tuple[CaseOutcome, ...]

    @property
    def true_positives(self) -> int:
        """Number of expected findings that were reported."""
        return sum(len(outcome.matched) for outcome in self.outcomes)

    @property
    def false_positives(self) -> int:
        """Number of findings that were not expected."""
        return sum(len(outcome.spurious) for outcome in self.outcomes)

    @property
    def false_negatives(self) -> int:
        """Number of expected findings that were missed."""
        return sum(len(outcome.missed) for outcome in self.outcomes)

    @property
    def precision(self) -> float:
        """Precision of the provider over the evaluation set."""
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        """Recall of the provider over the evaluation set."""
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        """F1 score of the provider over the evaluation set."""
        precision, recall = self.precision, self.recall
        if precision + recall == 0:
            return 0.0
        return 2 * precision * recall / (precision + recall)

    @property
    def exact_cases(self) -> int:
        """Number of cases that produced exactly the expected findings."""
        return sum(1 for outcome in self.outcomes if outcome.ok)

    @property
    def total_cases(self) -> int:
        """Number of evaluated cases."""
        return len(self.outcomes)

    def per_rule(self) -> dict[str, dict[str, int]]:
        """Return per rule hit/miss counts."""
        stats: dict[str, dict[str, int]] = {}
        for outcome in self.outcomes:
            for identifier in outcome.matched:
                entry = stats.setdefault(identifier, {"tp": 0, "fn": 0, "fp": 0})
                entry["tp"] += 1
            for identifier in outcome.missed:
                entry = stats.setdefault(identifier, {"tp": 0, "fn": 0, "fp": 0})
                entry["fn"] += 1
            for identifier in outcome.spurious:
                entry = stats.setdefault(identifier, {"tp": 0, "fn": 0, "fp": 0})
                entry["fp"] += 1
        return stats


def _make_unit(case: BenchCase) -> SourceUnit:
    kind, is_template = classify_from_case(case)
    return SourceUnit(
        path=None,  # type: ignore[arg-type]
        rel_path=case.filename,
        kind=kind,
        text=case.text,
        lines=tuple(case.text.splitlines()),
        size=len(case.text),
        is_template=is_template,
    )


def classify_from_case(case: BenchCase) -> tuple[FileKind, bool]:
    """Determine the file kind of a benchmark case."""
    try:
        kind, is_template = classify(Path(case.filename), case.filename)
    except (OSError, ValueError):  # pragma: no cover - defensive
        kind, is_template = FileKind.OTHER, case.template
    if case.template:
        is_template = True
    return kind, is_template


def _matches(expected: str, found: str) -> bool:
    if expected.endswith("*"):
        return found.startswith(expected[:-1])
    return expected == found


def select_cases(provider: Provider, cases: Sequence[BenchCase]) -> tuple[BenchCase, ...]:
    """Return the cases that apply to ``provider``.

    The deterministic provider is evaluated on the labelled rule cases, the
    model backends are evaluated on those *and* on the contextual cases that
    only a model can reason about.
    """
    if provider.model_capable:
        return tuple(cases)
    return tuple(case for case in cases if case.mode != "contextual")


def run_benchmark(
    provider: Provider,
    cases: Sequence[BenchCase] | None = None,
) -> BenchResult:
    """Run ``provider`` over the labelled evaluation set."""
    selected = select_cases(provider, tuple(cases) if cases is not None else load_cases())
    outcomes: list[CaseOutcome] = []
    for case in selected:
        unit = _make_unit(case)
        findings = provider.analyze_unit(unit)
        found = tuple(finding.id for finding in findings)
        model_findings = tuple(
            finding.id for finding in findings if finding.source == "model"
        )

        matched: list[str] = []
        missed: list[str] = []
        for expected in case.expect:
            if any(_matches(expected, item) for item in found) or (case.allow_any_model and model_findings):
                matched.append(expected)
            else:
                missed.append(expected)

        spurious = [
            item
            for item in found
            if not any(_matches(expected, item) for expected in case.expect)
            and not (case.allow_any_model and item in model_findings)
        ]
        outcomes.append(
            CaseOutcome(
                case_id=case.id,
                rationale=case.rationale,
                expected=case.expect,
                found=found,
                matched=tuple(matched),
                missed=tuple(missed),
                spurious=tuple(spurious),
            )
        )

    return BenchResult(
        provider=provider.name,
        model=provider.model,
        outcomes=tuple(outcomes),
    )


def format_bench_text(result: BenchResult) -> str:
    """Render benchmark results as text."""
    lines = [
        f"g4env benchmark  |  provider: {result.provider}"
        + (f" ({result.model})" if result.model else "")
        + "  |  cases: "
        + str(result.total_cases),
        "",
        f"precision: {result.precision:.3f}   recall: {result.recall:.3f}   f1: {result.f1:.3f}",
        f"exact cases: {result.exact_cases}/{result.total_cases}",
        f"tp: {result.true_positives}   fp: {result.false_positives}   fn: {result.false_negatives}",
        "",
    ]

    stats = result.per_rule()
    if stats:
        headers = ("RULE", "TP", "FN", "FP")
        rows = [
            (identifier, str(entry["tp"]), str(entry["fn"]), str(entry["fp"]))
            for identifier, entry in sorted(stats.items())
        ]
        widths = [len(header) for header in headers]
        for row in rows:
            for index, cell in enumerate(row):
                widths[index] = max(widths[index], len(cell))

        def format_row(cells: Sequence[str]) -> str:
            return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

        lines.append(format_row(headers))
        lines.append("  ".join("\u2500" * width for width in widths))
        for row in rows:
            lines.append(format_row(row))
        lines.append("")

    failures = [outcome for outcome in result.outcomes if not outcome.ok]
    if failures:
        lines.append("failures:")
        for outcome in failures:
            detail = []
            if outcome.missed:
                detail.append(f"missed {', '.join(outcome.missed)}")
            if outcome.spurious:
                detail.append(f"unexpected {', '.join(outcome.spurious)}")
            lines.append(f"  {outcome.case_id}: {'; '.join(detail)}")
    else:
        lines.append("all cases produced exactly the expected findings")
    return "\n".join(lines).rstrip() + "\n"


def format_bench_json(result: BenchResult) -> str:
    """Render benchmark results as JSON."""
    import json

    payload = {
        "provider": result.provider,
        "model": result.model,
        "cases": result.total_cases,
        "precision": round(result.precision, 4),
        "recall": round(result.recall, 4),
        "f1": round(result.f1, 4),
        "exact_cases": result.exact_cases,
        "true_positives": result.true_positives,
        "false_positives": result.false_positives,
        "false_negatives": result.false_negatives,
        "per_rule": result.per_rule(),
        "outcomes": [
            {
                "case": outcome.case_id,
                "expected": list(outcome.expected),
                "found": list(outcome.found),
                "matched": list(outcome.matched),
                "missed": list(outcome.missed),
                "spurious": list(outcome.spurious),
                "ok": outcome.ok,
            }
            for outcome in result.outcomes
        ],
    }
    return json.dumps(payload, indent=2)
