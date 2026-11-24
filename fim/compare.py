"""Diff two file maps and classify each difference."""

from dataclasses import dataclass
from typing import Optional

ADDED = "ADDED"
MODIFIED = "MODIFIED"
DELETED = "DELETED"
PERMISSION_CHANGED = "PERMISSION_CHANGED"


@dataclass
class Change:
    path: str
    change_type: str
    old: Optional[dict] = None
    new: Optional[dict] = None


def compare(old_files, new_files):
    """Return a sorted list of Change objects between two ``path -> record`` maps.

    MODIFIED is decided by hash only. A file whose content *and* permissions
    changed yields two changes (MODIFIED and PERMISSION_CHANGED). If a file's
    hash is unknown (unreadable) on either side, content is not compared.
    """
    changes = []
    for path in sorted(set(old_files) | set(new_files)):
        old = old_files.get(path)
        new = new_files.get(path)
        if old is None:
            changes.append(Change(path, ADDED, None, new))
        elif new is None:
            changes.append(Change(path, DELETED, old, None))
        else:
            if old["hash"] is not None and new["hash"] is not None and old["hash"] != new["hash"]:
                changes.append(Change(path, MODIFIED, old, new))
            if old.get("perm") != new.get("perm"):
                changes.append(Change(path, PERMISSION_CHANGED, old, new))
    return changes
