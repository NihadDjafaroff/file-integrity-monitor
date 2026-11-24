"""Hash algorithm selection."""

import hashlib

import pytest

from fim.errors import ConfigError
from fim.hashing import hash_bytes, hash_file


def test_default_is_sha256(env):
    doc, _, _ = env.init()
    assert doc["algorithm"] == "sha256"
    rec = next(r for p, r in doc["files"].items() if p.endswith("a.txt"))
    assert rec["hash"] == hashlib.sha256(b"alpha").hexdigest()


@pytest.mark.parametrize("algo,length", [("sha256", 64), ("sha512", 128), ("md5", 32)])
def test_algorithm_is_selectable_and_changes_stored_digest(env, algo, length):
    env.reconfigure(hash_algorithm=algo)
    doc, _, _ = env.init()
    rec = next(r for p, r in doc["files"].items() if p.endswith("a.txt"))
    assert doc["algorithm"] == algo
    assert rec["hash"] == hashlib.new(algo, b"alpha").hexdigest()
    assert len(rec["hash"]) == length


def test_init_cli_style_override_beats_config(env):
    doc, _, _ = env.init(algorithm="sha512")
    assert doc["algorithm"] == "sha512"


def test_scan_uses_the_baselines_algorithm_even_if_config_changes(env):
    env.reconfigure(hash_algorithm="sha512")
    env.init()
    env.reconfigure(hash_algorithm="md5")  # config drifted; baseline wins
    assert env.scan().alerts == []
    env.write("a.txt", "changed!")
    assert len(env.scan().alerts[0].new_hash) == 128


def test_unknown_algorithm_rejected(env):
    with pytest.raises(ConfigError, match="unsupported hash algorithm"):
        env.reconfigure(hash_algorithm="crc32")


def test_hash_file_matches_hash_bytes(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"x" * 3_000_000)  # larger than one read chunk
    for algo in ("sha256", "sha512", "md5"):
        assert hash_file(f, algo) == hash_bytes(b"x" * 3_000_000, algo)
