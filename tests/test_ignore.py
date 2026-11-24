"""Ignore / include patterns."""

import pytest

from fim.ignore import PatternSet


@pytest.mark.parametrize("path,expected", [
    ("a.swp", True), ("deep/dir/a.swp", True), ("a.txt", False),
    ("~lock", True), ("notes.txt~", True),
    (".DS_Store", True), ("x/Thumbs.db", True), ("x/.hidden.swp", True),
])
def test_default_style_basename_patterns(path, expected):
    from fim.config import DEFAULT_IGNORE
    assert PatternSet(DEFAULT_IGNORE, case_insensitive=False).match(path) is expected


def test_anchored_and_directory_patterns():
    ps = PatternSet(["build/", "/top.txt", "docs/*.md", "a/**/z.txt"], case_insensitive=False)
    assert ps.match("build/out.bin")          # parent dir matches -> contents match
    assert ps.match("src/build/out.bin")      # no slash inside -> any depth
    assert ps.match("top.txt") and not ps.match("sub/top.txt")
    assert ps.match("docs/readme.md") and not ps.match("docs/x/readme.md")
    assert ps.match("a/b/c/z.txt") and ps.match("a/z.txt")
    assert not ps.match("build")              # a *file* named build is not a dir pattern match


def test_negation_last_match_wins():
    ps = PatternSet(["*.log", "!keep.log"], case_insensitive=False)
    assert ps.match("x.log") and not ps.match("keep.log")


def test_ignored_files_do_not_alert(env):
    env.init()
    env.write(".a.txt.swp", "vim swap")
    env.write("~tmpfile", "x")
    env.write("scratch.tmp", "x")
    env.write(".DS_Store", "x")
    env.write("sub/Thumbs.db", "x")
    assert env.scan().alerts == []


def test_ignored_files_are_not_in_baseline(env):
    env.write("junk.swp", "x")
    doc, _, _ = env.init()
    assert not any(p.endswith("junk.swp") for p in doc["files"])


def test_custom_ignore_and_defaults_can_be_disabled(env):
    env.reconfigure(ignore=["*.log"])
    env.init()
    env.write("app.log", "noise")
    env.write("x.swp", "still ignored by defaults")
    assert env.scan().alerts == []

    env.reconfigure(ignore=[], use_default_ignore=False)
    env.write("y.swp", "now visible")
    # with no ignores at all, everything added so far shows up
    assert env.types(env.scan()) == [("app.log", "ADDED"), ("x.swp", "ADDED"), ("y.swp", "ADDED")]


def test_per_path_exclude_and_include(env):
    env.write("docs/a.md", "x")
    env.write("docs/b.txt", "x")
    env.reconfigure(paths=[{"path": str(env.root), "exclude": ["docs/"]}])
    env.init()
    env.write("docs/c.md", "x")
    assert env.scan().alerts == []

    env.reconfigure(
        paths=[{"path": str(env.root), "include": ["*.md"]}],
        state_dir=str(env.tmp / "state2"),
    )
    doc, _, _ = env.init()
    assert {p.rsplit("/", 1)[1] for p in doc["files"]} == {"a.md", "c.md"}
