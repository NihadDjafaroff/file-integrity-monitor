"""Signed baseline / snapshot storage.

Every stored document carries an HMAC-SHA256 over its canonical JSON form,
computed with a local secret key that lives *outside* the state directory. An
attacker who edits a monitored file and then "fixes up" the baseline to match
cannot produce a valid signature without the key.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from .errors import FimError, IntegrityError

FORMAT_VERSION = 1


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- key handling -----------------------------------------------------------

def ensure_key(key_file):
    """Create the HMAC key if it does not exist yet. Returns (key, created)."""
    p = Path(key_file)
    if p.is_file():
        return load_key(key_file), False
    p.parent.mkdir(parents=True, exist_ok=True)
    key_hex = secrets.token_hex(32)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(key_hex + "\n")
    return bytes.fromhex(key_hex), True


def load_key(key_file):
    p = Path(key_file)
    if not p.is_file():
        raise IntegrityError(
            "HMAC key not found at %s - cannot verify the baseline. "
            "Restore the key or re-run 'fim init'." % key_file
        )
    try:
        return bytes.fromhex(p.read_text(encoding="ascii").strip())
    except ValueError:
        raise IntegrityError("HMAC key file %s is malformed" % key_file)


# --- signing ----------------------------------------------------------------

def _canonical(doc):
    body = {k: v for k, v in doc.items() if k != "hmac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(doc, key):
    return hmac.new(key, _canonical(doc), hashlib.sha256).hexdigest()


def verify(doc, key):
    sig = doc.get("hmac")
    if not isinstance(sig, str):
        return False
    return hmac.compare_digest(sig, sign(doc, key))


def build_document(kind, snap_id, algorithm, paths, files, created=None):
    return {
        "version": FORMAT_VERSION,
        "id": snap_id,
        "kind": kind,
        "created": iso(created or utc_now()),
        "algorithm": algorithm,
        "paths": paths,
        "files": files,
    }


# --- store ------------------------------------------------------------------

_ID_RE = re.compile(r"^[A-Za-z0-9T_-]+$")


class SnapshotStore:
    def __init__(self, state_dir, key_file):
        self.state_dir = Path(state_dir)
        self.key_file = key_file

    @property
    def baseline_path(self):
        return self.state_dir / "baseline.json"

    @property
    def snapshots_dir(self):
        return self.state_dir / "snapshots"

    def new_id(self):
        base = utc_now().strftime("%Y%m%dT%H%M%SZ")
        snap_id, n = base, 0
        while (self.snapshots_dir / (snap_id + ".json")).exists():
            n += 1
            snap_id = "%s-%d" % (base, n)
        return snap_id

    def _write(self, path, doc):
        key = load_key(self.key_file)
        doc = dict(doc)
        doc["hmac"] = sign(doc, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(doc, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(str(tmp), str(path))

    def _read(self, path, what):
        if not path.is_file():
            raise FimError("%s not found: %s" % (what, path))
        key = load_key(self.key_file)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise IntegrityError("%s %s is unreadable or not valid JSON" % (what, path))
        if not isinstance(doc, dict) or not verify(doc, key):
            raise IntegrityError(
                "%s %s failed HMAC verification - it was modified outside of fim "
                "(or the key changed)" % (what, path)
            )
        return doc

    def save_baseline(self, doc):
        self._write(self.baseline_path, doc)

    def load_baseline(self):
        return self._read(self.baseline_path, "baseline")

    def save_snapshot(self, doc):
        self._write(self.snapshots_dir / (doc["id"] + ".json"), doc)

    def load(self, ref):
        """Load a snapshot by id; the literal 'baseline' loads the baseline."""
        if ref == "baseline":
            return self.load_baseline()
        if not _ID_RE.match(ref):
            raise FimError("invalid snapshot id: %r" % ref)
        return self._read(self.snapshots_dir / (ref + ".json"), "snapshot")

    def list_ids(self):
        if not self.snapshots_dir.is_dir():
            return []
        return sorted(p.stem for p in self.snapshots_dir.glob("*.json"))
