"""HMAC protection of the baseline / snapshots (threat: attacker edits fim's own state)."""

import json
import os

import pytest

from fim.errors import IntegrityError
from fim.snapshot import ensure_key, sign, verify
from fim.watch import watch


def _edit_baseline(env, mutate):
    path = env.mon.store.baseline_path
    doc = json.loads(path.read_text())
    mutate(doc)
    path.write_text(json.dumps(doc))  # direct edit, bypassing the tool (HMAC left stale)


def test_untouched_baseline_verifies(env):
    env.init()
    assert env.scan().alerts == []


def test_tampering_with_a_recorded_hash_is_detected(env):
    """Attacker modifies a file, then rewrites its hash in the baseline to hide it."""
    env.init()
    env.write("a.txt", "backdoor")
    new_hash = env.scan().alerts[0].new_hash

    def hide(doc):
        key = next(k for k in doc["files"] if k.endswith("a.txt"))
        doc["files"][key]["hash"] = new_hash

    _edit_baseline(env, hide)
    with pytest.raises(IntegrityError, match="HMAC"):
        env.scan()


def test_removing_a_baseline_entry_is_detected(env):
    env.init()
    _edit_baseline(env, lambda d: d["files"].pop(next(iter(d["files"]))))
    with pytest.raises(IntegrityError):
        env.scan()


def test_shrinking_monitored_scope_is_detected(env):
    env.init()
    _edit_baseline(env, lambda d: d.update(paths=[]))
    with pytest.raises(IntegrityError):
        env.scan()


def test_stripping_the_hmac_field_is_detected(env):
    env.init()
    _edit_baseline(env, lambda d: d.pop("hmac"))
    with pytest.raises(IntegrityError):
        env.scan()


def test_corrupt_json_is_an_integrity_failure(env):
    env.init()
    env.mon.store.baseline_path.write_text("{ not json")
    with pytest.raises(IntegrityError):
        env.scan()


def test_baseline_signed_with_a_different_key_is_rejected(env):
    env.init()
    # An attacker without the key cannot re-sign; simulate by swapping the key.
    os.remove(env.key)
    ensure_key(env.key)
    with pytest.raises(IntegrityError):
        env.scan()


def test_missing_key_fails_closed(env):
    env.init()
    os.remove(env.key)
    with pytest.raises(IntegrityError, match="key not found"):
        env.scan()


def test_tampered_snapshot_is_rejected_by_diff(env):
    env.init()
    env.write("n.txt", "x")
    env.scan()
    sid = env.mon.store.list_ids()[-1]
    p = env.mon.store.snapshots_dir / (sid + ".json")
    doc = json.loads(p.read_text())
    doc["files"].clear()
    p.write_text(json.dumps(doc))
    with pytest.raises(IntegrityError):
        env.mon.diff("baseline", sid)


def test_watch_verifies_every_cycle_and_stops_on_tamper(env):
    env.init()
    cycles = []

    def sleeper(_):
        cycles.append(1)
        _edit_baseline(env, lambda d: d.update(created="1999-01-01T00:00:00Z"))

    import io
    with pytest.raises(IntegrityError):
        watch(env.mon, io.StringIO(), io.StringIO(), interval=0, sleep=sleeper, max_scans=5)
    assert len(cycles) == 1  # first scan clean, tamper after it, second scan fails


def test_sign_verify_primitives():
    key = b"k" * 32
    doc = {"a": 1, "b": [1, 2]}
    doc["hmac"] = sign(doc, key)
    assert verify(doc, key)
    assert not verify({**doc, "a": 2}, key)
    assert not verify(doc, b"x" * 32)


def test_key_file_is_created_once_and_reused(tmp_path):
    kf = tmp_path / "k" / "fim.key"
    k1, created1 = ensure_key(kf)
    k2, created2 = ensure_key(kf)
    assert created1 and not created2 and k1 == k2 and len(k1) == 32
