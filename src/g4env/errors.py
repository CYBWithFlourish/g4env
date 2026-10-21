"""Exception hierarchy shared by the g4env subsystems.

The CLI maps these onto the documented exit-code contract:

``0``
    Success.
``1``
    Operational or analysis error (:class:`OperationalError` and subclasses).
``2``
    Usage error - raised by :mod:`argparse` before g4env is involved.
``3``
    Policy violation - a finding met or exceeded ``--fail-on``.
"""

from __future__ import annotations


class G4EnvError(Exception):
    """Base class for every error raised by g4env itself."""


class OperationalError(G4EnvError):
    """Raised when an audit cannot be completed (bad input, missing provider)."""


class UsageError(G4EnvError):
    """Raised for invalid flags or arguments supplied by the user."""


class ProviderError(OperationalError):
    """Raised when an analysis backend is unavailable or misbehaves."""


class InputError(OperationalError):
    """Raised when an audit target cannot be read or is not safe to process."""


class SchemaError(OperationalError):
    """Raised when a generated report fails validation against the schema."""
