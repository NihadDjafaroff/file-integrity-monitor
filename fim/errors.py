"""Exception types used across the tool."""


class FimError(Exception):
    """Base class for expected, user-facing errors."""


class ConfigError(FimError):
    """The configuration file is missing or invalid."""


class IntegrityError(FimError):
    """A baseline/snapshot failed HMAC verification (possible tampering)."""
