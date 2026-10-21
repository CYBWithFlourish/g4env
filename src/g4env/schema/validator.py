"""JSON schema storage, loading and validation.

g4env validates every report it produces against a versioned JSON schema.
The validator implemented here is a small, dependency free subset of
JSON Schema draft-07 that covers exactly the keywords used by the report
schema. Keeping it in-tree means the default (offline) provider never needs
a third-party package.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from g4env.errors import SchemaError

__all__ = [
    "SCHEMA_DIR",
    "SchemaValidationError",
    "load_schema",
    "validate",
]

SCHEMA_DIR = Path(__file__).resolve().parent

_SCHEMA_FILES = {
    "1.0": SCHEMA_DIR / "report_v1.json",
}


class SchemaValidationError(SchemaError):
    """Raised when an instance does not satisfy the report schema."""


def schema_path(version: str) -> Path:
    """Return the on-disk location of the schema for ``version``."""
    try:
        return _SCHEMA_FILES[version]
    except KeyError as exc:
        known = ", ".join(sorted(_SCHEMA_FILES))
        raise SchemaError(f"unknown report schema version {version!r}; known versions: {known}") from exc


@lru_cache(maxsize=8)
def load_schema(version: str) -> dict[str, Any]:
    """Load and cache the JSON schema for ``version``."""
    path = schema_path(version)
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:  # pragma: no cover - packaging failure
        raise SchemaError(f"report schema {version!r} is missing from the installation") from exc
    except json.JSONDecodeError as exc:  # pragma: no cover - packaging failure
        raise SchemaError(f"report schema {version!r} is not valid JSON: {exc}") from exc


def _resolve_ref(ref: str, root: dict[str, Any]) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise SchemaValidationError(f"unsupported schema reference: {ref!r}")
    node: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise SchemaValidationError(f"unresolvable schema reference: {ref!r}")
        node = node[part]
    if not isinstance(node, dict):
        raise SchemaValidationError(f"schema reference does not point at a schema: {ref!r}")
    return node


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise SchemaValidationError(f"unsupported schema type: {expected!r}")


def validate(instance: Any, schema: dict[str, Any], *, root: dict[str, Any] | None = None) -> list[str]:
    """Validate ``instance`` against ``schema`` and return a list of errors.

    The returned list is empty when the instance is valid.
    """
    root = root if root is not None else schema
    errors: list[str] = []

    if "$ref" in schema:
        errors.extend(validate(instance, _resolve_ref(schema["$ref"], root), root=root))
        # A schema with $ref may still carry sibling keywords; keep validating.
        siblings = {key: value for key, value in schema.items() if key != "$ref"}
        if siblings:
            errors.extend(validate(instance, siblings, root=root))
        return errors

    if "const" in schema and instance != schema["const"]:
        errors.append(f"expected constant {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        allowed = ", ".join(repr(item) for item in schema["enum"])
        errors.append(f"value {instance!r} is not one of: {allowed}")

    expected_type = schema.get("type")
    if expected_type is not None:
        expected_types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_type_matches(instance, item) for item in expected_types):
            errors.append(f"expected type {'/'.join(expected_types)}, got {type(instance).__name__}")
            return errors

    if isinstance(instance, str):
        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, instance) is None:
            errors.append(f"value {instance!r} does not match pattern {pattern!r}")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"value is shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"value is longer than maxLength {schema['maxLength']}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"value {instance} is below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"value {instance} is above maximum {schema['maximum']}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"array has fewer than minItems {schema['minItems']}")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"array has more than maxItems {schema['maxItems']}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                errors.extend(
                    f"[{index}]{suffix}"
                    for suffix in validate(item, item_schema, root=root)
                )

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"missing required property {key!r}")
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                errors.extend(
                    f".{key}{suffix}" for suffix in validate(value, properties[key], root=root)
                )
            elif additional is False:
                errors.append(f"unexpected property {key!r}")
            elif isinstance(additional, dict):
                errors.extend(
                    f".{key}{suffix}" for suffix in validate(value, additional, root=root)
                )

    for keyword in ("anyOf", "oneOf"):
        if keyword not in schema:
            continue
        matches = sum(
            1
            for option in schema[keyword]
            if not validate(instance, option, root=root)
        )
        if keyword == "anyOf" and matches == 0:
            errors.append("value does not match any of the allowed schemas")
        if keyword == "oneOf" and matches != 1:
            errors.append(f"value must match exactly one allowed schema (matched {matches})")

    return errors
