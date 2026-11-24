"""Historical snapshots and `fim diff`."""

import os

import pytest

from fim.errors import FimError


def test_init_stores_a_snapshot_and_baseline(env):
    doc, _, _ = env.init()
    assert env.mon.store.list_ids() == [doc["id"]]
    assert env.mon.store.load(doc["id"])["files"] == doc["files"]
    assert env.mon.store.load("baseline")["id"] == doc["id"]


def test_default_policy_snapshots_only_scans_that_find_changes(env):
    env.init()
    clean = env.scan()
    assert not env.mon.should_snapshot(clean)
    assert len(env.mon.store.list_ids()) == 1

    env.write("new.txt", "x")
    dirty = env.scan()
    assert env.mon.should_snapshot(dirty)
    sid = env.mon.save_snapshot(dirty)
    assert sid in env.mon.store.list_ids()
    assert env.mon.store.load(sid)["kind"] == "scan"


@pytest.mark.parametrize("policy,clean_saves", [("always", True), ("never", False), ("changes", False)])
def test_snapshot_policy_for_clean_scans(env, policy, clean_saves):
    env.reconfigure(snapshot_on_scan=policy)
    env.init()
    assert env.mon.should_snapshot(env.scan()) is clean_saves


def test_snapshot_ids_are_unique_even_within_one_second(env):
    env.init()
    ids = {env.mon.save_snapshot(env.scan()) for _ in range(3)}
    assert len(ids) == 3


def test_diff_between_two_snapshots_reports_the_delta(env):
    base, _, _ = env.init()
    env.write("a.txt", "modified")
    os.remove(env.root / "sub" / "b.txt")
    env.write("new.txt", "added")
    mid = env.mon.save_snapshot(env.scan())

    env.write("new.txt", "added, then edited")
    late = env.mon.save_snapshot(env.scan())

    _, _, alerts = env.mon.diff(base["id"], mid)
    assert sorted((os.path.basename(a.path), a.change_type) for a in alerts) == [
        ("a.txt", "MODIFIED"), ("b.txt", "DELETED"), ("new.txt", "ADDED"),
    ]
    # timeline reconstruction: only the later edit separates mid -> late
    a_doc, b_doc, alerts = env.mon.diff(mid, late)
    assert [(os.path.basename(a.path), a.change_type) for a in alerts] == [("new.txt", "MODIFIED")]
    assert alerts[0].timestamp == b_doc["created"]


def test_diff_accepts_baseline_keyword_and_identical_snapshots_are_empty(env):
    base, _, _ = env.init()
    _, _, alerts = env.mon.diff("baseline", base["id"])
    assert alerts == []


def test_diff_unknown_or_malformed_id(env):
    env.init()
    with pytest.raises(FimError, match="not found"):
        env.mon.diff("baseline", "20990101T000000Z")
    with pytest.raises(FimError, match="invalid snapshot id"):
        env.mon.diff("baseline", "../../etc/passwd")


def test_update_baseline_accepts_current_state(env):
    env.init()
    env.write("new.txt", "x")
    result = env.scan()
    assert result.alerts
    env.mon.accept(result)
    assert env.scan().alerts == []
