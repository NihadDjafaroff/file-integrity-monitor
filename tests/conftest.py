import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fim.config import config_from_dict  # noqa: E402
from fim.monitor import Monitor  # noqa: E402


def bump_mtime(path, seconds=5):
    """Push a file's mtime forward (so the size/mtime pre-filter sees a change)."""
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + seconds * 1_000_000_000))


class Env:
    """A throwaway monitored directory plus state/key locations, all under tmp_path."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.root = tmp_path / "watched"
        self.root.mkdir()
        (self.root / "a.txt").write_text("alpha")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.txt").write_text("bravo")
        self.state = tmp_path / "state"
        self.key = tmp_path / "keys" / "fim.key"
        self.config_path = tmp_path / "fim.yaml"
        self.reconfigure()

    def reconfigure(self, **overrides):
        data = {
            "paths": [str(self.root)],
            "state_dir": str(self.state),
            "key_file": str(self.key),
        }
        data.update(overrides)
        self.cfg = config_from_dict(data, base_dir=self.tmp)
        self.mon = Monitor(self.cfg)
        return self.mon

    def init(self, **kw):
        return self.mon.init(**kw)

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def scan(self, **kw):
        return self.mon.scan(**kw)

    def types(self, result):
        return sorted((os.path.basename(a.path), a.change_type) for a in result.alerts)


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)
