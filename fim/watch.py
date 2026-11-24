"""Continuous monitoring: polling (default, dependency-free) or filesystem events."""

import os
import threading
import time

from .alerts import emit
from .errors import FimError
from .response import quarantine


class EventTrigger:
    """Wake the watch loop on filesystem events (requires ``watchdog``)."""

    def __init__(self, roots, skip_paths, debounce=0.5):
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            raise FimError(
                "--mode events needs the optional 'watchdog' package "
                "(pip install watchdog); polling mode works without it"
            )
        self._event = threading.Event()
        self._debounce = debounce
        skips = [os.path.normcase(os.path.abspath(s)) for s in skip_paths if s]
        trigger = self

        class _Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                src = os.path.normcase(os.path.abspath(str(event.src_path)))
                if any(src == s or src.startswith(s + os.sep) for s in skips):
                    return  # our own state/quarantine writes must not retrigger
                trigger._event.set()

        self._observer = Observer()
        scheduled = 0
        for root in roots:
            path = os.path.abspath(os.path.expanduser(root["path"]))
            if os.path.isfile(path):
                path = os.path.dirname(path)
            if os.path.isdir(path):
                self._observer.schedule(_Handler(), path, recursive=True)
                scheduled += 1
        if not scheduled:
            raise FimError("no existing directories to watch")
        self._observer.start()

    def wait(self, timeout):
        fired = self._event.wait(timeout)
        if fired:
            time.sleep(self._debounce)  # coalesce bursts of events
            self._event.clear()
        return fired

    def stop(self):
        self._observer.stop()
        self._observer.join(timeout=5)


def watch(monitor, out, err, *, interval=30.0, mode="poll", fmt="text",
          enable_response=False, full_hash=False, max_scans=None, sleep=time.sleep):
    """Run scans until interrupted (or ``max_scans`` reached).

    The baseline is re-read and HMAC-verified on *every* cycle, so tampering
    with it while the watcher runs is caught on the next scan (IntegrityError
    propagates and ends the loop). Each distinct finding is reported once;
    it is reported again only if it disappears and later recurs.
    Returns the list of alerts reported.
    """
    cfg = monitor.cfg
    trigger = None
    if mode == "events":
        base = monitor.store.load_baseline()  # verified before we trust its scope
        trigger = EventTrigger(base["paths"], cfg.skip_paths)
    elif mode != "poll":
        raise FimError("unknown mode %r" % mode)

    reported, seen, scans = [], set(), 0
    try:
        while True:
            result = monitor.scan(full_hash=full_hash)
            current = {a.key() for a in result.alerts}
            new = [a for a in result.alerts if a.key() not in seen]
            seen = current
            for w in result.stats.warnings:
                print("warning: " + w, file=err)
            if new:
                emit(new, out, fmt, cfg.log_file)
                if monitor.should_snapshot(result, new):
                    monitor.save_snapshot(result)
                if enable_response:
                    for a in new:
                        quarantine(a, cfg.quarantine_dir, cfg.log_file, err)
                reported.extend(new)
            elif cfg.snapshot_on_scan == "always":
                monitor.save_snapshot(result)
            scans += 1
            if max_scans is not None and scans >= max_scans:
                break
            if trigger:
                trigger.wait(interval)
            else:
                sleep(interval)
    except KeyboardInterrupt:
        print("watch stopped", file=err)
    finally:
        if trigger:
            trigger.stop()
    return reported
