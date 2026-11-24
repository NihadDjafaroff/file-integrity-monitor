"""Risk-based severity classification."""

import stat

import pytest

from fim.compare import ADDED, DELETED, MODIFIED, PERMISSION_CHANGED, Change
from fim.config import DEFAULT_CRITICAL
from fim.severity import CRITICAL, HIGH, LOW, MEDIUM, SeverityClassifier


def rec(mode=0o644, h="aa"):
    return {"hash": h, "perm": {"mode": mode}}


@pytest.fixture
def clf():
    return SeverityClassifier(DEFAULT_CRITICAL)


@pytest.mark.parametrize("ctype", [ADDED, MODIFIED, DELETED, PERMISSION_CHANGED])
def test_critical_path_is_critical_for_every_change_type(env, ctype):
    crit = env.root / "etc" / "passwd"
    env.write("etc/passwd", "root:x:0:0")
    env.reconfigure(critical_paths=["**/etc/passwd"])
    env.init()
    if ctype == ADDED:
        crit.unlink()
        env.init(force=True)
        env.write("etc/passwd", "root:x:0:0")
    elif ctype == MODIFIED:
        crit.write_text("root:x:0:0\nevil:x:0:0")
    elif ctype == DELETED:
        crit.unlink()
    else:
        import os
        orig = stat.S_IMODE(os.stat(crit).st_mode)
        os.chmod(crit, 0o444)
    try:
        result = env.scan()
    finally:
        if ctype == PERMISSION_CHANGED:
            os.chmod(crit, orig)
    assert [(a.change_type, a.severity) for a in result.alerts] == [(ctype, CRITICAL)]


def test_non_critical_file_is_not_flagged_critical(env):
    env.reconfigure(critical_paths=["**/etc/passwd"])
    env.write("etc/passwd", "x")
    env.write("notes.txt", "x")
    env.init()
    env.write("notes.txt", "changed")
    result = env.scan()
    assert [a.severity for a in result.alerts] == [MEDIUM]


@pytest.mark.parametrize("path", [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers.d/90-evil", "/etc/cron.d/job",
    "/var/spool/cron/root", "/home/bob/.ssh/authorized_keys",
    "C:/Users/bob/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.lnk",
    "C:/Windows/System32/drivers/etc/hosts",
])
def test_default_critical_list_covers_linux_and_windows(clf, path):
    assert clf.is_critical(path)


@pytest.mark.parametrize("path", ["/etc/hostname", "/home/bob/notes.txt", "/tmp/passwd.bak"])
def test_default_critical_list_does_not_overmatch(clf, path):
    assert not clf.is_critical(path)


def test_tilde_in_user_pattern_expands_to_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    from fim.config import config_from_dict
    cfg = config_from_dict({"critical_paths": ["~/.bashrc"], "use_default_critical": False})
    c = SeverityClassifier(cfg.critical_patterns)
    assert c.is_critical((tmp_path / ".bashrc").as_posix())


def test_heuristics_for_non_critical_paths(clf):
    c = lambda t, p, old=None, new=None: clf.classify(Change(p, t, old, new))  # noqa: E731
    assert c(ADDED, "/data/readme.txt", None, rec()) == LOW
    assert c(ADDED, "/data/run.sh", None, rec()) == HIGH
    assert c(ADDED, "/data/payload.exe", None, rec()) == HIGH
    assert c(MODIFIED, "/data/readme.txt", rec(), rec(h="bb")) == MEDIUM
    assert c(MODIFIED, "/data/tool.ps1", rec(), rec(h="bb")) == HIGH
    assert c(DELETED, "/data/readme.txt", rec(), None) == MEDIUM
    assert c(PERMISSION_CHANGED, "/data/readme.txt", rec(0o644), rec(0o600)) == LOW
    assert c(PERMISSION_CHANGED, "/data/readme.txt", rec(0o644), rec(0o666)) == HIGH   # world-writable
    assert c(PERMISSION_CHANGED, "/data/readme.txt", rec(0o755), rec(0o4755)) == HIGH  # setuid
    assert c(PERMISSION_CHANGED, "/data/readme.txt", rec(0o666), rec(0o644)) == LOW    # tightening
