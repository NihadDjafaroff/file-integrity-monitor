"""JSON alert output, opt-in quarantine response, and watch mode."""

import io
import json
import os

import pytest

from fim.alerts import emit
from fim.errors import FimError
from fim.response import quarantine
from fim.watch import watch


def test_json_alert_fields(env):
    env.init()
    env.write("a.txt", "changed")
    env.write("new.txt", "x")
    out = io.StringIO()
    emit(env.scan().alerts, out, "json")
    objs = [json.loads(line) for line in out.getvalue().splitlines()]
    assert len(objs) == 2
    for o in objs:
        assert {"path", "change_type", "severity", "old_hash", "new_hash", "timestamp"} <= set(o)
    by = {os.path.basename(o["path"]): o for o in objs}
    assert by["a.txt"]["old_hash"] and by["a.txt"]["new_hash"]
    assert by["new.txt"]["old_hash"] is None and by["new.txt"]["new_hash"]


def test_alerts_appended_to_json_log_file(env, tmp_path):
    log = tmp_path / "logs" / "alerts.jsonl"
    env.init()
    env.write("a.txt", "changed")
    emit(env.scan().alerts, io.StringIO(), "text", log)
    emit(env.scan().alerts, io.StringIO(), "text", log)
    lines = log.read_text().splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["change_type"] == "MODIFIED"


def test_text_output_is_ascii_and_readable(env):
    env.init()
    env.write("a.txt", "changed")
    out = io.StringIO()
    emit(env.scan().alerts, out, "text")
    line = out.getvalue()
    assert "[MEDIUM" in line and "MODIFIED" in line and line.isascii()


# --- response -----------------------------------------------------------------

def _critical_env(env):
    env.write("etc/passwd", "root:x:0:0")
    env.reconfigure(critical_paths=["**/etc/passwd"])
    env.init()
    env.write("etc/passwd", "root:x:0:0\nevil::0:0")
    return env.root / "etc" / "passwd"


def test_response_is_off_by_default(env):
    target = _critical_env(env)
    result = env.scan()
    assert result.alerts[0].severity == "CRITICAL"
    assert target.exists()  # scan alone never touches files


def test_quarantine_moves_critical_file_and_logs_why(env, tmp_path):
    target = _critical_env(env)
    log = tmp_path / "alerts.jsonl"
    err = io.StringIO()
    alert = env.scan().alerts[0]
    rec = quarantine(alert, env.cfg.quarantine_dir, log, err)
    assert not target.exists()
    assert os.path.isfile(rec["quarantine_path"])
    assert rec["original_path"] == alert.path and "CRITICAL" in rec["reason"]
    assert alert.path in err.getvalue()
    logged = json.loads(log.read_text().splitlines()[-1])
    assert logged["event"] == "QUARANTINE" and logged["original_path"] == alert.path


def test_quarantine_ignores_non_critical_and_deleted(env):
    target = _critical_env(env)
    env.write("plain.txt", "x")
    alerts = {os.path.basename(a.path): a for a in env.scan().alerts}
    assert quarantine(alerts["plain.txt"], env.cfg.quarantine_dir) is None
    assert (env.root / "plain.txt").exists()
    target.unlink()
    deleted = [a for a in env.scan().alerts if a.change_type == "DELETED"][0]
    assert quarantine(deleted, env.cfg.quarantine_dir) is None


def test_quarantine_dir_inside_monitored_tree_is_not_monitored(env):
    env.reconfigure(quarantine_dir=str(env.root / "quarantine"), critical_paths=["**/a.txt"])
    env.init()
    env.write("a.txt", "evil")
    for a in env.scan().alerts:
        quarantine(a, env.cfg.quarantine_dir)
    # a.txt now DELETED (moved); the quarantine copy must not appear as ADDED
    assert [a.change_type for a in env.scan().alerts] == ["DELETED"]


# --- watch ----------------------------------------------------------------------

def test_watch_reports_each_finding_once_and_snapshots(env):
    env.init()
    out, err = io.StringIO(), io.StringIO()
    steps = iter([
        lambda: env.write("new.txt", "x"),   # appears after scan 1
        lambda: None,                         # unchanged -> must not re-alert
        lambda: env.write("a.txt", "edit"),  # new finding
    ])

    def sleeper(_):
        next(steps)()

    alerts = watch(env.mon, out, err, interval=0, sleep=sleeper, max_scans=4)
    assert [(os.path.basename(a.path), a.change_type) for a in alerts] == [
        ("new.txt", "ADDED"), ("a.txt", "MODIFIED"),
    ]
    assert len(out.getvalue().splitlines()) == 2
    assert len(env.mon.store.list_ids()) == 3  # init + two scans that found something new


def test_watch_response_requires_opt_in(env):
    target = _critical_env(env)
    watch(env.mon, io.StringIO(), io.StringIO(), interval=0, max_scans=1)
    assert target.exists()
    watch(env.mon, io.StringIO(), io.StringIO(), interval=0, max_scans=1, enable_response=True)
    assert not target.exists()


def test_events_mode_without_watchdog_fails_cleanly(env, monkeypatch):
    env.init()
    import builtins
    real_import = builtins.__import__

    def fake(name, *a, **k):
        if name.startswith("watchdog"):
            raise ImportError("no watchdog")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(FimError, match="watchdog"):
        watch(env.mon, io.StringIO(), io.StringIO(), mode="events", max_scans=1)
