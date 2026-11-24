"""Alert objects plus text / JSON-lines output."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .compare import PERMISSION_CHANGED


def _mode_str(perm):
    if not perm or "mode" not in perm:
        return None
    return "0%o" % perm["mode"]


@dataclass
class Alert:
    path: str
    change_type: str
    severity: str
    timestamp: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    old_perm: Optional[dict] = None
    new_perm: Optional[dict] = None

    def key(self):
        """Identity used by watch mode to avoid re-reporting the same finding."""
        return (
            self.path, self.change_type, self.new_hash,
            json.dumps(self.new_perm, sort_keys=True),
        )

    def to_dict(self):
        d = {
            "timestamp": self.timestamp,
            "path": self.path,
            "change_type": self.change_type,
            "severity": self.severity,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
        }
        if self.change_type == PERMISSION_CHANGED:
            d["old_mode"] = _mode_str(self.old_perm)
            d["new_mode"] = _mode_str(self.new_perm)
            d["old_perm"] = self.old_perm
            d["new_perm"] = self.new_perm
        return d

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True)

    def to_text(self):
        line = "%s [%-8s] %-18s %s" % (self.timestamp, self.severity, self.change_type, self.path)
        if self.change_type == PERMISSION_CHANGED:
            line += "  mode %s -> %s" % (_mode_str(self.old_perm), _mode_str(self.new_perm))
        elif self.old_hash or self.new_hash:
            line += "  %s -> %s" % (_short(self.old_hash), _short(self.new_hash))
        return line


def _short(h):
    return h[:12] if h else "-"


def make_alert(change, severity, timestamp):
    return Alert(
        path=change.path,
        change_type=change.change_type,
        severity=severity,
        timestamp=timestamp,
        old_hash=(change.old or {}).get("hash"),
        new_hash=(change.new or {}).get("hash"),
        old_perm=(change.old or {}).get("perm"),
        new_perm=(change.new or {}).get("perm"),
    )


def append_log(log_file, obj):
    """Append one JSON object per line to the structured alert log."""
    if not log_file:
        return
    p = Path(log_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, sort_keys=True) + "\n")


def emit(alerts, out, fmt="text", log_file=None):
    """Print alerts (text or JSON lines) and append them to the JSON log."""
    for a in alerts:
        print(a.to_json() if fmt == "json" else a.to_text(), file=out)
        append_log(log_file, a.to_dict())
    try:
        out.flush()
    except Exception:
        pass
