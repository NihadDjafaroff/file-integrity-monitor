"""Risk-based severity scoring.

Heuristic (first match wins):

1. Path matches a configured *critical* pattern            -> CRITICAL (any change type)
2. Permission change that gains setuid/setgid/world-write  -> HIGH
3. ADDED or MODIFIED executable / script                   -> HIGH
4. Any other MODIFIED or DELETED file                      -> MEDIUM
5. Any other ADDED file, any other permission change       -> LOW

This is deliberately simple: it demonstrates SOC-style alert prioritisation
rather than being a perfect classifier.
"""

import os
import stat

from .compare import ADDED, DELETED, MODIFIED, PERMISSION_CHANGED
from .ignore import PatternSet

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
RANK = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

EXECUTABLE_EXTENSIONS = {
    ".sh", ".bash", ".py", ".pl", ".rb", ".php", ".exe", ".dll", ".sys", ".so",
    ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr", ".com", ".jar", ".service",
}

_DANGEROUS_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH


class SeverityClassifier:
    def __init__(self, critical_patterns):
        self.critical = PatternSet(critical_patterns)

    def is_critical(self, path):
        return self.critical.match(path.lstrip("/"))

    def classify(self, change):
        if self.is_critical(change.path):
            return CRITICAL
        ctype = change.change_type
        if ctype == PERMISSION_CHANGED:
            old_mode = (change.old.get("perm") or {}).get("mode", 0)
            new_mode = (change.new.get("perm") or {}).get("mode", 0)
            return HIGH if (new_mode & ~old_mode) & _DANGEROUS_BITS else LOW
        record = change.new or change.old
        if ctype in (ADDED, MODIFIED) and _looks_executable(change.path, record):
            return HIGH
        if ctype in (MODIFIED, DELETED):
            return MEDIUM
        return LOW


def _looks_executable(path, record):
    if os.path.splitext(path)[1].lower() in EXECUTABLE_EXTENSIONS:
        return True
    mode = ((record or {}).get("perm") or {}).get("mode", 0)
    # Windows reports exec bits for everything, so only trust them on POSIX.
    return os.name != "nt" and bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
