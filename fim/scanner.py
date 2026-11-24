"""Filesystem walking and two-phase hashing.

Phase 1 (cheap): ``lstat`` every file. If size and mtime match the previous
record, reuse the stored hash. Phase 2 (expensive): only files whose size or
mtime differ (or that are new) are actually read and hashed.
"""

import os
import stat
from dataclasses import dataclass, field

from .hashing import hash_bytes, hash_file
from .ignore import PatternSet

_owner_supported = True


def normalize(path):
    """Absolute path with forward slashes - the key used everywhere."""
    return os.path.abspath(path).replace(os.sep, "/")


def _windows_owner(path):
    global _owner_supported
    if not _owner_supported:
        return None
    try:
        from pathlib import Path
        return Path(path).owner()
    except (NotImplementedError, OSError, KeyError, ImportError):
        _owner_supported = False  # Python < 3.13 on Windows has no owner lookup
        return None


def permissions(st, path):
    """Portable permission record.

    POSIX: mode bits + uid/gid. Windows: simplified - the read-only flag
    (reflected in the mode bits) and, where Python can resolve it, the owner.
    Full ACL comparison is out of scope.
    """
    mode = stat.S_IMODE(st.st_mode)
    if os.name == "nt":
        return {
            "mode": mode,
            "readonly": not (mode & stat.S_IWRITE),
            "owner": _windows_owner(path),
        }
    return {"mode": mode, "uid": st.st_uid, "gid": st.st_gid}


@dataclass
class ScanStats:
    files: int = 0
    hashed: int = 0
    reused: int = 0
    warnings: list = field(default_factory=list)


def _is_under(path, skip):
    p = os.path.normcase(os.path.abspath(path))
    s = os.path.normcase(os.path.abspath(skip))
    return p == s or p.startswith(s + os.sep)


def _record(path, previous, algorithm, stats):
    try:
        st = os.lstat(path)
    except OSError as exc:
        stats.warnings.append("cannot stat %s: %s" % (path, exc))
        return None
    is_link = stat.S_ISLNK(st.st_mode)
    if not (is_link or stat.S_ISREG(st.st_mode)):
        return None  # sockets, fifos, devices: reading them could block
    key = normalize(path)
    prev = previous.get(key) if previous else None
    if (
        prev is not None
        and prev.get("hash") is not None
        and prev.get("size") == st.st_size
        and prev.get("mtime_ns") == st.st_mtime_ns
    ):
        digest = prev["hash"]
        stats.reused += 1
    else:
        stats.hashed += 1
        try:
            if is_link:  # hash the link target text; never follow the link
                digest = hash_bytes(os.readlink(path).encode("utf-8", "surrogateescape"), algorithm)
            else:
                digest = hash_file(path, algorithm)
        except OSError as exc:
            digest = None
            stats.warnings.append("cannot read %s: %s" % (path, exc))
    stats.files += 1
    return key, {
        "hash": digest,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "perm": permissions(st, path),
    }


def scan_roots(roots, algorithm, ignore_patterns, previous=None, skip_paths=(), full_hash=False):
    """Scan monitored roots. Returns ``(files, stats)``.

    ``roots`` is a list of dicts: ``{"path", "include", "exclude"}``.
    ``previous`` maps path -> record from the baseline (enables phase-1 reuse).
    ``full_hash`` disables the mtime/size shortcut and hashes everything.
    """
    stats = ScanStats()
    files = {}
    prev = None if full_hash else previous
    skip_paths = [s for s in skip_paths if s]

    for root in roots:
        top = os.path.abspath(os.path.expanduser(root["path"]))
        excl = PatternSet(list(ignore_patterns) + list(root.get("exclude") or []))
        incl = PatternSet(root.get("include") or [])

        if not os.path.isdir(top):
            if os.path.lexists(top):  # a single monitored file
                if not any(_is_under(top, s) for s in skip_paths):
                    rec = _record(top, prev, algorithm, stats)
                    if rec:
                        files[rec[0]] = rec[1]
            else:
                stats.warnings.append("monitored path does not exist: %s" % top)
            continue

        def on_error(exc, _stats=stats):
            _stats.warnings.append("cannot list %s: %s" % (exc.filename, exc))

        for dirpath, dirnames, filenames in os.walk(top, onerror=on_error):
            rel_dir = os.path.relpath(dirpath, top).replace(os.sep, "/")
            rel_dir = "" if rel_dir == "." else rel_dir
            dirnames[:] = sorted(
                d for d in dirnames
                if not excl.match((rel_dir + "/" + d).lstrip("/"), is_dir=True)
                and not any(_is_under(os.path.join(dirpath, d), s) for s in skip_paths)
            )
            for name in sorted(filenames):
                rel = (rel_dir + "/" + name).lstrip("/")
                full = os.path.join(dirpath, name)
                if excl.match(rel):
                    continue
                if incl and not incl.match(rel):
                    continue
                if any(_is_under(full, s) for s in skip_paths):
                    continue
                rec = _record(full, prev, algorithm, stats)
                if rec:
                    files[rec[0]] = rec[1]
    return files, stats
