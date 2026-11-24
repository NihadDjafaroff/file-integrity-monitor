"""High-level operations: init, scan, snapshot persistence, diff."""

from dataclasses import dataclass, field

from .alerts import make_alert
from .compare import compare
from .errors import ConfigError, FimError
from .hashing import check_algorithm
from .scanner import ScanStats, scan_roots
from .severity import SeverityClassifier
from .snapshot import SnapshotStore, build_document, ensure_key, iso, utc_now


@dataclass
class ScanResult:
    baseline: dict
    files: dict
    alerts: list
    stats: ScanStats
    timestamp: str
    snapshot_id: str = ""
    changes: list = field(default_factory=list)


class Monitor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.store = SnapshotStore(cfg.state_dir, cfg.key_file)

    # -- init ---------------------------------------------------------------
    def init(self, paths=None, algorithm=None, force=False):
        """Create the baseline (and the HMAC key if this is the first run).

        Returns ``(document, stats, key_created)``.
        """
        paths = paths if paths is not None else self.cfg.paths
        if not paths:
            raise ConfigError("no paths to monitor: use --path or set 'paths' in the config")
        if self.store.baseline_path.exists() and not force:
            raise FimError(
                "a baseline already exists at %s (use --force to replace it)"
                % self.store.baseline_path
            )
        algo = check_algorithm(algorithm or self.cfg.hash_algorithm)
        _, key_created = ensure_key(self.cfg.key_file)
        roots = [p.to_dict() for p in paths]
        files, stats = scan_roots(roots, algo, self.cfg.ignore_patterns, None, self.cfg.skip_paths)
        doc = build_document("baseline", self.store.new_id(), algo, roots, files)
        self.store.save_baseline(doc)
        self.store.save_snapshot(doc)
        return doc, stats, key_created

    # -- scan ---------------------------------------------------------------
    def scan(self, full_hash=False):
        """Verify the baseline's HMAC, re-scan, and classify every difference.

        Monitored scope and hash algorithm come from the (signed) baseline, so
        editing the config cannot silently shrink what is being watched.
        """
        base = self.store.load_baseline()
        files, stats = scan_roots(
            base["paths"], base["algorithm"], self.cfg.ignore_patterns,
            previous=base["files"], skip_paths=self.cfg.skip_paths, full_hash=full_hash,
        )
        changes = compare(base["files"], files)
        ts = iso(utc_now())
        clf = SeverityClassifier(self.cfg.critical_patterns)
        alerts = [make_alert(c, clf.classify(c), ts) for c in changes]
        return ScanResult(base, files, alerts, stats, ts, changes=changes)

    def save_snapshot(self, result):
        """Persist the scanned state as a timestamped, signed snapshot."""
        b = result.baseline
        doc = build_document("scan", self.store.new_id(), b["algorithm"], b["paths"], result.files)
        self.store.save_snapshot(doc)
        result.snapshot_id = doc["id"]
        return doc["id"]

    def should_snapshot(self, result, new_alerts=None):
        policy = self.cfg.snapshot_on_scan
        if policy == "never":
            return False
        if policy == "always":
            return True
        return bool(result.alerts if new_alerts is None else new_alerts)

    def accept(self, result):
        """Adopt the scanned state as the new baseline (re-signed)."""
        b = result.baseline
        doc = build_document("baseline", self.store.new_id(), b["algorithm"], b["paths"], result.files)
        self.store.save_baseline(doc)
        self.store.save_snapshot(doc)
        return doc["id"]

    # -- diff ---------------------------------------------------------------
    def diff(self, ref_a, ref_b):
        a = self.store.load(ref_a)
        b = self.store.load(ref_b)
        if a["algorithm"] != b["algorithm"]:
            raise FimError(
                "snapshots use different hash algorithms (%s vs %s); cannot compare"
                % (a["algorithm"], b["algorithm"])
            )
        changes = compare(a["files"], b["files"])
        clf = SeverityClassifier(self.cfg.critical_patterns)
        # The change was observed no later than snapshot B was taken.
        alerts = [make_alert(c, clf.classify(c), b["created"]) for c in changes]
        return a, b, alerts
