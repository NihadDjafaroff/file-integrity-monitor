"""Two-phase scanning: mtime/size pre-filter before hashing."""

import os

from conftest import bump_mtime
from fim import scanner


def _count_hashes(monkeypatch):
    calls = []
    real = scanner.hash_file

    def counting(path, algorithm):
        calls.append(os.path.basename(path))
        return real(path, algorithm)

    monkeypatch.setattr(scanner, "hash_file", counting)
    return calls


def test_unchanged_files_are_not_rehashed(env, monkeypatch):
    env.init()
    calls = _count_hashes(monkeypatch)
    result = env.scan()
    assert calls == []
    assert result.stats.reused == 2 and result.stats.hashed == 0


def test_only_files_with_new_mtime_or_size_are_rehashed(env, monkeypatch):
    env.init()
    env.write("a.txt", "alpha but longer")  # size changes
    calls = _count_hashes(monkeypatch)
    result = env.scan()
    assert calls == ["a.txt"]
    assert result.stats.reused == 1 and result.stats.hashed == 1
    assert env.types(result) == [("a.txt", "MODIFIED")]


def test_real_change_with_new_mtime_and_size_is_always_caught(env):
    env.init()
    env.write("a.txt", "completely different content")
    bump_mtime(env.root / "a.txt")
    assert env.types(env.scan()) == [("a.txt", "MODIFIED")]


def test_same_size_content_change_with_new_mtime_is_caught(env):
    env.init()
    env.write("a.txt", "ALPHA")  # same length as "alpha"
    bump_mtime(env.root / "a.txt")
    assert env.types(env.scan()) == [("a.txt", "MODIFIED")]


def test_documented_edge_case_same_size_and_mtime_is_missed_by_default(env):
    """Known limitation of any mtime/size pre-filter: an attacker who rewrites a
    file with identical length AND restores its mtime evades the fast path.
    ``--full-hash`` exists to close that gap."""
    env.init()
    target = env.root / "a.txt"
    st = os.stat(target)
    target.write_text("ALPHA")                       # same size, different bytes
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))  # restore mtime

    assert env.scan().alerts == []                   # fast path trusts size+mtime
    full = env.scan(full_hash=True)                  # full re-hash catches it
    assert env.types(full) == [("a.txt", "MODIFIED")]
    assert full.stats.reused == 0
