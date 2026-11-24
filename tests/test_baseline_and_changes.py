"""Baseline creation/reload and classification of ADDED / MODIFIED / DELETED / PERMISSION_CHANGED."""

import json
import os
import stat

import pytest

from conftest import bump_mtime
from fim.errors import FimError
from fim.scanner import normalize


def test_baseline_records_every_file_with_metadata(env):
    doc, stats, key_created = env.init()
    assert key_created
    assert set(doc["files"]) == {normalize(env.root / "a.txt"), normalize(env.root / "sub" / "b.txt")}
    rec = doc["files"][normalize(env.root / "a.txt")]
    assert rec["size"] == 5 and rec["mtime_ns"] > 0
    assert len(rec["hash"]) == 64  # sha256 hex
    assert "mode" in rec["perm"]
    assert doc["algorithm"] == "sha256"


def test_baseline_reload_roundtrip_and_key_stored_separately(env):
    doc, _, _ = env.init()
    loaded = env.mon.store.load_baseline()
    assert loaded["files"] == doc["files"]
    assert loaded["paths"] == doc["paths"]
    # key must not live in the state dir (which holds the baseline)
    assert env.key.is_file()
    assert env.state not in env.key.parents


def test_init_refuses_to_overwrite_without_force(env):
    env.init()
    with pytest.raises(FimError, match="already exists"):
        env.init()
    env.init(force=True)  # explicit opt-in works


def test_clean_scan_reports_nothing(env):
    env.init()
    assert env.scan().alerts == []


def test_added_file_detected(env):
    env.init()
    env.write("new.txt", "hello")
    assert env.types(env.scan()) == [("new.txt", "ADDED")]


def test_modified_file_detected_via_hash(env):
    env.init()
    env.write("a.txt", "ALPHA!")
    result = env.scan()
    assert env.types(result) == [("a.txt", "MODIFIED")]
    alert = result.alerts[0]
    assert alert.old_hash and alert.new_hash and alert.old_hash != alert.new_hash


def test_touch_without_content_change_is_not_modified(env):
    env.init()
    bump_mtime(env.root / "a.txt")  # mtime differs -> re-hash -> same hash
    assert env.scan().alerts == []


def test_deleted_file_detected(env):
    env.init()
    os.remove(env.root / "sub" / "b.txt")
    result = env.scan()
    assert env.types(result) == [("b.txt", "DELETED")]
    assert result.alerts[0].new_hash is None


def test_permission_change_detected(env):
    env.init()
    target = env.root / "a.txt"
    original = stat.S_IMODE(os.stat(target).st_mode)
    os.chmod(target, 0o444)
    try:
        result = env.scan()
    finally:
        os.chmod(target, original)
    assert env.types(result) == [("a.txt", "PERMISSION_CHANGED")]
    d = result.alerts[0].to_dict()
    assert d["old_mode"] != d["new_mode"]


def test_content_and_permission_change_yield_two_findings(env):
    env.init()
    target = env.root / "a.txt"
    original = stat.S_IMODE(os.stat(target).st_mode)
    target.write_text("changed")
    os.chmod(target, 0o444)
    try:
        result = env.scan()
    finally:
        os.chmod(target, original)
    assert env.types(result) == [("a.txt", "MODIFIED"), ("a.txt", "PERMISSION_CHANGED")]


def test_nested_directories_are_scanned_recursively(env):
    env.write("x/y/z/deep.txt", "deep")
    env.init()
    env.write("x/y/z/deep.txt", "deeper")
    assert env.types(env.scan()) == [("deep.txt", "MODIFIED")]


def test_scan_without_baseline_is_a_clear_error(env):
    with pytest.raises(FimError, match="baseline not found"):
        env.scan()


def test_scope_comes_from_signed_baseline_not_config(env):
    """Editing the config's paths cannot shrink what an existing baseline watches."""
    env.init()
    other = env.tmp / "other"
    other.mkdir()
    env.reconfigure(paths=[str(other)])
    env.write("a.txt", "tampered")
    assert env.types(env.scan()) == [("a.txt", "MODIFIED")]


def test_baseline_file_is_plain_json_with_hmac(env):
    env.init()
    doc = json.loads(env.mon.store.baseline_path.read_text())
    assert len(doc["hmac"]) == 64
    assert doc["kind"] == "baseline"
