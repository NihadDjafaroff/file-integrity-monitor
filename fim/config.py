"""YAML configuration loading and defaults."""

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .errors import ConfigError
from .hashing import DEFAULT_ALGORITHM, check_algorithm

# Transient / noisy files that are not real integrity events.
DEFAULT_IGNORE = [
    "*.swp", "*.swo", "*.swx", ".*.sw?",   # vim swap files
    "*~", "~*", ".#*",                      # editor backups / lock files
    "*.tmp", "*.temp",
    ".DS_Store", "Thumbs.db", "desktop.ini",  # OS cruft
]

# Paths whose modification is security-relevant regardless of change type.
# Matched against the absolute, forward-slash path with the same syntax as the
# ignore patterns. A leading "~" is expanded to the user's home directory.
DEFAULT_CRITICAL = [
    # Linux / macOS
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/sudoers.d/**",
    "/etc/ssh/sshd_config",
    "/etc/hosts", "/etc/ld.so.preload",
    "/etc/crontab", "/etc/cron.d/**", "/etc/cron.hourly/**",
    "/etc/cron.daily/**", "/etc/cron.weekly/**", "/etc/cron.monthly/**",
    "/var/spool/cron/**",
    "/etc/systemd/system/**",
    "**/.ssh/authorized_keys",
    # Windows (matched case-insensitively)
    "**/Windows/System32/drivers/etc/hosts",
    "**/Windows/System32/config/**",
    "**/Windows/System32/Tasks/**",
    "**/Start Menu/Programs/Startup/**",
    "**/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/**",
]

SNAPSHOT_POLICIES = ("changes", "always", "never")


def default_key_file():
    return str(Path.home() / ".fim" / "fim.key")


@dataclass
class WatchPath:
    path: str
    include: list = field(default_factory=list)
    exclude: list = field(default_factory=list)

    def to_dict(self):
        return {"path": self.path, "include": list(self.include), "exclude": list(self.exclude)}


@dataclass
class Config:
    paths: list = field(default_factory=list)
    hash_algorithm: str = DEFAULT_ALGORITHM
    ignore: list = field(default_factory=list)
    use_default_ignore: bool = True
    critical_paths: list = field(default_factory=list)
    use_default_critical: bool = True
    state_dir: str = ".fim"
    key_file: str = ""
    quarantine_dir: str = ""
    log_file: str = ""
    snapshot_on_scan: str = "changes"
    interval: float = 30.0

    def __post_init__(self):
        self.hash_algorithm = check_algorithm(self.hash_algorithm)
        if self.snapshot_on_scan not in SNAPSHOT_POLICIES:
            raise ConfigError(
                "snapshot_on_scan must be one of: " + ", ".join(SNAPSHOT_POLICIES)
            )
        if not self.key_file:
            self.key_file = default_key_file()
        if not self.quarantine_dir:
            self.quarantine_dir = str(Path(self.state_dir) / "quarantine")

    @property
    def baseline_path(self):
        return Path(self.state_dir) / "baseline.json"

    @property
    def snapshots_dir(self):
        return Path(self.state_dir) / "snapshots"

    @property
    def ignore_patterns(self):
        base = list(DEFAULT_IGNORE) if self.use_default_ignore else []
        return base + list(self.ignore)

    @property
    def critical_patterns(self):
        base = list(DEFAULT_CRITICAL) if self.use_default_critical else []
        out = []
        for p in base + list(self.critical_paths):
            p = str(p)
            if p.startswith("~"):
                p = Path(p).expanduser().as_posix()
            out.append(p)
        return out

    @property
    def skip_paths(self):
        """Files/dirs belonging to the tool itself; never monitored."""
        return [self.state_dir, self.quarantine_dir, self.key_file]


def _as_list(value, name):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    raise ConfigError("%r must be a list of strings" % name)


def _resolve(base_dir, value):
    p = Path(os.path.expanduser(str(value)))
    if not p.is_absolute():
        p = Path(base_dir) / p
    return str(Path(os.path.abspath(p)))


def parse_paths(entries, base_dir="."):
    paths = []
    for entry in entries or []:
        if isinstance(entry, str):
            entry = {"path": entry}
        if not isinstance(entry, dict) or "path" not in entry:
            raise ConfigError("each item in 'paths' must be a string or a mapping with 'path'")
        paths.append(
            WatchPath(
                path=_resolve(base_dir, entry["path"]),
                include=_as_list(entry.get("include"), "include"),
                exclude=_as_list(entry.get("exclude"), "exclude"),
            )
        )
    return paths


def config_from_dict(data, base_dir="."):
    if not isinstance(data, dict):
        raise ConfigError("configuration must be a YAML mapping")
    known = {
        "paths", "hash_algorithm", "ignore", "use_default_ignore", "critical_paths",
        "use_default_critical", "state_dir", "key_file", "quarantine_dir", "log_file",
        "snapshot_on_scan", "interval",
    }
    unknown = set(data) - known
    if unknown:
        raise ConfigError("unknown configuration key(s): " + ", ".join(sorted(unknown)))
    state_dir = _resolve(base_dir, data.get("state_dir", ".fim"))
    kwargs = dict(
        paths=parse_paths(data.get("paths"), base_dir),
        hash_algorithm=data.get("hash_algorithm", DEFAULT_ALGORITHM),
        ignore=_as_list(data.get("ignore"), "ignore"),
        use_default_ignore=bool(data.get("use_default_ignore", True)),
        critical_paths=_as_list(data.get("critical_paths"), "critical_paths"),
        use_default_critical=bool(data.get("use_default_critical", True)),
        state_dir=state_dir,
        snapshot_on_scan=str(data.get("snapshot_on_scan", "changes")),
    )
    if data.get("key_file"):
        kwargs["key_file"] = _resolve(base_dir, data["key_file"])
    if data.get("quarantine_dir"):
        kwargs["quarantine_dir"] = _resolve(base_dir, data["quarantine_dir"])
    if data.get("log_file"):
        kwargs["log_file"] = _resolve(base_dir, data["log_file"])
    try:
        kwargs["interval"] = float(data.get("interval", 30))
    except (TypeError, ValueError):
        raise ConfigError("'interval' must be a number of seconds")
    return Config(**kwargs)


def load_config(path):
    """Load a YAML config. Relative paths inside it resolve against its directory."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError("config file not found: %s" % path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError("invalid YAML in %s: %s" % (path, exc))
    return config_from_dict(data, base_dir=p.resolve().parent)
