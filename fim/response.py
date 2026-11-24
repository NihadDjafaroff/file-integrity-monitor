"""Optional, opt-in auto-response: quarantine files behind CRITICAL alerts.

Never runs unless the caller explicitly enables it (``--enable-response``).
"""

import os
import shutil
from pathlib import Path

from .alerts import append_log
from .compare import ADDED, MODIFIED, PERMISSION_CHANGED
from .severity import CRITICAL
from .snapshot import iso, utc_now

QUARANTINABLE = (ADDED, MODIFIED, PERMISSION_CHANGED)


def quarantine(alert, quarantine_dir, log_file=None, err=None):
    """Move the file behind a CRITICAL alert into ``quarantine_dir``.

    Returns the log record, or None if the alert is not eligible / the file is
    gone. The record (original path, new path, reason) is also appended to the
    JSON alert log and printed to ``err``.
    """
    if alert.severity != CRITICAL or alert.change_type not in QUARANTINABLE:
        return None
    if not os.path.isfile(alert.path):
        return None
    now = utc_now()
    qdir = Path(quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)
    flat = alert.path.replace("/", "_").replace(":", "")
    dest = qdir / ("%s__%s" % (now.strftime("%Y%m%dT%H%M%S"), flat))
    n = 0
    while dest.exists():
        n += 1
        dest = qdir / ("%s__%s.%d" % (now.strftime("%Y%m%dT%H%M%S"), flat, n))
    shutil.move(alert.path, str(dest))
    record = {
        "event": "QUARANTINE",
        "timestamp": iso(now),
        "original_path": alert.path,
        "quarantine_path": str(dest).replace(os.sep, "/"),
        "reason": "%s %s on a critical path" % (alert.severity, alert.change_type),
    }
    append_log(log_file, record)
    if err is not None:
        print(
            "[RESPONSE] quarantined %s -> %s (%s)"
            % (record["original_path"], record["quarantine_path"], record["reason"]),
            file=err,
        )
    return record
