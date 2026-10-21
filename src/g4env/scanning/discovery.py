"""Discovery of auditable files below a target path."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from g4env.scanning.ignore import IgnoreRules
from g4env.scanning.loader import FileKind, max_file_bytes

__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_FILES",
    "Candidate",
    "classify",
    "discover",
    "is_template_name",
]

#: Maximum number of files audited in a single run.
DEFAULT_MAX_FILES = 5000

#: Maximum directory depth walked below the target.
DEFAULT_MAX_DEPTH = 20

#: Directories that never contain auditable configuration.
SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        "node_modules",
        "bower_components",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cache",
        ".parcel-cache",
        ".turbo",
        ".gradle",
        ".idea",
        ".vscode",
        ".terraform",
        "dist",
        "build",
        "out",
        ".eggs",
        "site-packages",
        "vendor",
        "coverage",
        "htmlcov",
        "target",
        "Pods",
        "DerivedData",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".serverless",
        "var",
        "tmp",
    }
)

#: File suffixes that are never text configuration.
SKIP_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".tiff",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".whl",
        ".egg",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".bin",
        ".o",
        ".a",
        ".class",
        ".jar",
        ".pyc",
        ".pyo",
        ".pyd",
        ".wasm",
        ".node",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".mkv",
        ".wav",
        ".flac",
        ".sqlite",
        ".sqlite3",
        ".db",
        ".mdb",
        ".pkl",
        ".pickle",
        ".npy",
        ".npz",
        ".pt",
        ".pth",
        ".onnx",
        ".safetensors",
        ".model",
        ".ckpt",
        ".lock",
    }
)

#: Suffixes that map onto a known file kind.
CONFIG_SUFFIXES = frozenset(
    {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".env"}
)

SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".vue",
        ".svelte",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".go",
        ".rb",
        ".java",
        ".kt",
        ".kts",
        ".rs",
        ".php",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".cs",
        ".swift",
        ".scala",
        ".ex",
        ".exs",
        ".erl",
        ".lua",
        ".pl",
        ".pm",
        ".r",
        ".dart",
        ".tf",
        ".hcl",
        ".gradle",
        ".ipynb",
    }
)

#: Files and directories that hold CI/CD pipeline definitions.
_CI_FILE_NAMES = frozenset(
    {
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        "bitbucket-pipelines.yml",
        ".travis.yml",
        "appveyor.yml",
        "cloudbuild.yaml",
        "cloudbuild.yml",
        "buildspec.yml",
        "buildspec.yaml",
        "Jenkinsfile",
        "drone.yml",
        "woodpecker.yml",
        "wercker.yml",
        "shippable.yml",
    }
)

_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".distexample")


@dataclass(frozen=True)
class Candidate:
    """A file that may be audited."""

    path: Path
    rel_path: str
    kind: FileKind
    is_template: bool
    size: int


def is_template_name(name: str) -> bool:
    """Return ``True`` when the file name looks like a template or example."""
    lowered = name.lower()
    if lowered in {".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"}:
        return True
    if lowered.startswith(".env.") and lowered.endswith((".example", ".sample", ".template", ".dist")):
        return True
    for suffix in _TEMPLATE_SUFFIXES:
        if lowered.endswith(suffix):
            return True
    if lowered.endswith(".env.example") or lowered.endswith(".env.sample"):
        return True
    # Names such as docker-compose.template.yml carry the marker in the stem.
    stem = Path(lowered).stem
    return any(stem.endswith(suffix) for suffix in _TEMPLATE_SUFFIXES)


def classify(path: Path, rel_path: str) -> tuple[FileKind, bool]:
    """Determine the kind and template status of ``path``."""
    name = path.name
    lowered = name.lower()
    parts = [part.lower() for part in Path(rel_path).parts]

    is_template = is_template_name(name)

    if lowered in _CI_FILE_NAMES or name.startswith("Jenkinsfile") or name.endswith("Jenkinsfile"):
        return FileKind.CI, is_template
    if ".github/workflows" in "/".join(parts) and path.suffix.lower() in {".yml", ".yaml"}:
        return FileKind.CI, is_template
    if ".circleci" in parts and lowered.startswith("config."):
        return FileKind.CI, is_template
    if path.suffix.lower() == ".yaml" and lowered.startswith("cloudbuild"):
        return FileKind.CI, is_template

    if lowered == ".env" or lowered.startswith(".env.") or lowered.endswith(".env"):
        return FileKind.ENV, is_template
    if lowered in {"env", "env.local", "env.dev", "env.prod"}:
        return FileKind.ENV, is_template

    suffix = path.suffix.lower()
    if suffix in CONFIG_SUFFIXES:
        return FileKind.CONFIG, is_template
    if suffix in SOURCE_SUFFIXES or name in {"Dockerfile", "Makefile"}:
        return FileKind.SOURCE, is_template
    return FileKind.OTHER, is_template


def load_ignore_rules(root: Path) -> IgnoreRules:
    """Load the ignore rules that apply to ``root``."""
    rules = IgnoreRules()
    for name in (".g4envignore", ".gitignore"):
        candidate = root / name
        if candidate.is_file():
            try:
                rules.extend(candidate.read_text(encoding="utf-8", errors="replace"))
            except OSError:  # pragma: no cover - unreadable ignore file
                continue
    return rules


#: Backwards compatible private alias.
_load_ignore_rules = load_ignore_rules


def discover(
    root: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> list[Candidate]:
    """Return the auditable files below ``root``.

    A file target yields exactly one candidate. A directory target is walked
    while skipping vendored dependencies, build output, binary files and
    anything excluded by ``.gitignore``/``.g4envignore``.
    """
    limit = max_file_bytes()
    if root.is_file():
        kind, is_template = classify(root, root.name)
        try:
            size = root.stat().st_size
        except OSError:
            size = 0
        return [
            Candidate(
                path=root,
                rel_path=root.name,
                kind=kind,
                is_template=is_template,
                size=size,
            )
        ]

    rules = _load_ignore_rules(root)
    candidates: list[Candidate] = []
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        try:
            depth = len(current.relative_to(root).parts)
        except ValueError:  # pragma: no cover - defensive
            depth = 0

        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in SKIP_DIRECTORIES
            and not name.startswith(".g4env-")
            and not (depth + 1 >= max_depth)
        )

        for filename in sorted(filenames):
            if len(candidates) >= max_files:
                return candidates
            path = current / filename
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            try:
                rel_path = path.relative_to(root).as_posix()
            except ValueError:  # pragma: no cover - defensive
                continue
            if rules.is_ignored(rel_path):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > limit:
                continue
            kind, is_template = classify(path, rel_path)
            candidates.append(
                Candidate(
                    path=path,
                    rel_path=rel_path,
                    kind=kind,
                    is_template=is_template,
                    size=size,
                )
            )
    return candidates
