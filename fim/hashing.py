"""File hashing with a small set of selectable algorithms."""

import hashlib

from .errors import ConfigError

DEFAULT_ALGORITHM = "sha256"
SUPPORTED_ALGORITHMS = ("sha256", "sha512", "md5")
_CHUNK = 1024 * 1024


def check_algorithm(name):
    """Return the normalised algorithm name or raise ConfigError."""
    algo = str(name).lower()
    if algo not in SUPPORTED_ALGORITHMS:
        raise ConfigError(
            "unsupported hash algorithm %r (choose from: %s)"
            % (name, ", ".join(SUPPORTED_ALGORITHMS))
        )
    return algo


def _new_hasher(algorithm):
    algo = check_algorithm(algorithm)
    if algo == "md5":
        # MD5 is offered for legacy/speed use only; flag it as non-security use
        # so it also works on FIPS-restricted builds.
        return hashlib.new("md5", usedforsecurity=False)
    return hashlib.new(algo)


def hash_bytes(data, algorithm=DEFAULT_ALGORITHM):
    h = _new_hasher(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_file(path, algorithm=DEFAULT_ALGORITHM):
    """Stream a file through the chosen hash and return the hex digest."""
    h = _new_hasher(algorithm)
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
