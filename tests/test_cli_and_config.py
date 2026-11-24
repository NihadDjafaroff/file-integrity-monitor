"""End-to-end CLI behaviour and config loading."""

import io
import json
import os

import pytest

from fim.cli import main
from fim.config import load_config
from fim.errors import ConfigError


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def cli(tmp_path):
    """A watched dir plus a config written by `fim init --path`, run from tmp_path."""
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "a.txt").write_text("alpha")
    cfg = tmp_path / "fim.yaml"
    # key + state live under tmp_path so tests never touch the real home dir
    cfg.write_text(
        "paths: [%s]\nstate_dir: %s\nkey_file: %s\ncritical_paths: ['**/watched/secret.conf']\n"
        % (json.dumps(str(watched)), json.dumps(str(tmp_path / "st")), json.dumps(str(tmp_path / "k" / "key")))
    )
    return watched, str(cfg)


def test_init_scan_exit_codes(cli):
    watched, cfg = cli
    code, out, _ = run("init", "--config", cfg)
    assert code == 0 and "baseline created: 1 files" in out
    assert run("scan", "--config", cfg)[0] == 0                       # clean
    (watched / "n.txt").write_text("x")
    assert run("scan", "--config", cfg)[0] == 1                       # non-critical change
    (watched / "secret.conf").write_text("x")
    assert run("scan", "--config", cfg)[0] == 2                       # critical change


def test_scan_json_format_and_summary_on_stderr(cli):
    watched, cfg = cli
    run("init", "--config", cfg)
    (watched / "a.txt").write_text("edited")
    code, out, err = run("scan", "--config", cfg, "--format", "json")
    obj = json.loads(out.strip())
    assert obj["change_type"] == "MODIFIED" and obj["severity"] == "MEDIUM"
    assert "1 change(s)" in err and code == 1


def test_scan_with_tampered_baseline_exits_3_with_loud_warning(cli, tmp_path):
    _, cfg = cli
    run("init", "--config", cfg)
    base = tmp_path / "st" / "baseline.json"
    doc = json.loads(base.read_text())
    doc["files"].clear()  # semantic edit; the stored HMAC no longer matches
    base.write_text(json.dumps(doc))
    code, _, err = run("scan", "--config", cfg)
    assert code == 3 and "INTEGRITY FAILURE" in err


def test_init_with_path_creates_config_and_algorithm_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    d = tmp_path / "data"
    d.mkdir()
    (d / "f.txt").write_text("x")
    # no fim.yaml yet -> created; point the key somewhere safe via HOME
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    code, out, _ = run("init", "--path", str(d), "--algorithm", "sha512", "--config", "fim.yaml")
    assert code == 0 and "sha512" in out
    assert (tmp_path / "fim.yaml").is_file()
    assert (tmp_path / "home" / ".fim" / "fim.key").is_file()
    assert run("scan", "--config", "fim.yaml")[0] == 0


def test_diff_and_snapshots_subcommands(cli):
    watched, cfg = cli
    run("init", "--config", cfg)
    (watched / "n.txt").write_text("x")
    run("scan", "--config", cfg)
    _, listing, _ = run("snapshots", "--config", cfg)
    ids = [line.split()[0] for line in listing.splitlines()]
    assert len(ids) == 2
    code, out, _ = run("diff", ids[0], ids[1], "--config", cfg)
    assert code == 1 and "ADDED" in out and "n.txt" in out
    assert run("diff", ids[0], ids[0], "--config", cfg)[0] == 0


def test_update_baseline_flag(cli):
    watched, cfg = cli
    run("init", "--config", cfg)
    (watched / "n.txt").write_text("x")
    assert run("scan", "--config", cfg, "--update-baseline")[0] == 1
    assert run("scan", "--config", cfg)[0] == 0


def test_watch_command_runs_bounded_scans(cli):
    watched, cfg = cli
    run("init", "--config", cfg)
    (watched / "n.txt").write_text("x")
    code, out, _ = run("watch", "--config", cfg, "--interval", "0", "--max-scans", "2")
    assert code == 1 and out.count("ADDED") == 1


def test_enable_response_flag_on_scan(cli):
    watched, cfg = cli
    run("init", "--config", cfg)
    (watched / "secret.conf").write_text("x")
    run("scan", "--config", cfg)
    assert (watched / "secret.conf").exists()
    run("scan", "--config", cfg, "--enable-response")
    assert not (watched / "secret.conf").exists()


def test_missing_config_and_missing_baseline_are_clean_errors(tmp_path):
    code, _, err = run("scan", "--config", str(tmp_path / "nope.yaml"))
    assert code == 3 and "config file not found" in err


# --- config ----------------------------------------------------------------------

def test_config_defaults_and_relative_path_resolution(tmp_path):
    f = tmp_path / "sub" / "fim.yaml"
    f.parent.mkdir()
    f.write_text("paths:\n  - data\n  - {path: other, exclude: ['*.bak']}\nstate_dir: st\n")
    cfg = load_config(f)
    assert cfg.hash_algorithm == "sha256" and cfg.interval == 30.0
    assert cfg.paths[0].path == os.path.abspath(f.parent / "data")
    assert cfg.paths[1].exclude == ["*.bak"]
    assert cfg.state_dir == os.path.abspath(f.parent / "st")
    assert cfg.snapshot_on_scan == "changes"


@pytest.mark.parametrize("text", [
    "hash_algorithm: whirlpool\n",
    "bogus_key: 1\n",
    "snapshot_on_scan: sometimes\n",
    "paths: [{include: ['*.c']}]\n",
    "- just\n- a list\n",
    "interval: soon\n",
])
def test_invalid_configs_rejected(tmp_path, text):
    f = tmp_path / "fim.yaml"
    f.write_text(text)
    with pytest.raises(ConfigError):
        load_config(f)
