# fim - File Integrity Monitor

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-107%20passing-brightgreen)
![Deps](https://img.shields.io/badge/deps-pyyaml%20(watchdog%20optional)-lightgrey)

A command-line File Integrity Monitor (FIM). It records a cryptographic baseline of the
files you care about and then reports **ADDED**, **MODIFIED**, **DELETED** and
**PERMISSION_CHANGED** files, each scored **CRITICAL / HIGH / MEDIUM / LOW**. The baseline
itself is **HMAC-signed**, so tampering with the monitor's own state is detected too.

## Why

File integrity monitoring is a core blue-team control (it appears in PCI-DSS 11.5, CIS
Controls, and is the backbone of tools like OSSEC/Wazuh syscheck, AIDE and Tripwire).
After an intrusion, attackers edit `/etc/passwd`, drop an SSH key into `authorized_keys`,
add a cron job or replace a binary - and then try to cover their tracks. This project
demonstrates the full chain a SOC analyst cares about: detect -> prioritise -> preserve
evidence -> protect the detector.

Its JSON-lines alert output (`--format json` / `log_file`) is designed to be shipped into a
detection pipeline - e.g. as an input to the `sysmon-triage` / Wazuh work elsewhere in this
portfolio. No integration code is included.

## Features

| | |
|---|---|
| Baseline + scan | Recursive scan; stores hash, size, mtime, permissions per file |
| Change types | `ADDED`, `MODIFIED` (hash-based), `DELETED`, `PERMISSION_CHANGED` |
| Watch mode | Polling loop (default, no extra deps) or `--mode events` via `watchdog` |
| Ignore patterns | `.gitignore`-style globs, sensible defaults (`*.swp`, `~*`, `*.tmp`, `.DS_Store`, `Thumbs.db`) |
| Risk scoring | Configurable critical-path list + heuristics (see below) |
| Hash algorithms | `sha256` (default), `sha512`, `md5` |
| Signed state | HMAC-SHA256 over baseline and every snapshot; key stored separately |
| Snapshots + diff | Timestamped signed snapshots; `fim diff` any two |
| Fast scans | Two-phase: mtime/size pre-filter, hash only what changed |
| Structured output | One JSON object per alert; optional JSON-lines log file |
| Opt-in response | `--enable-response` quarantines files behind CRITICAL alerts |

## Install

```bash
git clone https://github.com/NihadDjafaroff/file-integrity-monitor && cd file-integrity-monitor
pip install -r requirements.txt        # pyyaml, pytest, (optional) watchdog
python -m fim --help                   # or: pip install -e .  ->  `fim ...`
```

Python 3.9+. Runs on Linux, macOS and Windows.

## Usage

```
fim init   --path <dir> [--path <dir> ...] [--config fim.yaml] [--algorithm sha256|sha512|md5] [--force]
fim scan   [--config fim.yaml] [--format text|json] [--full-hash] [--update-baseline] [--enable-response]
fim watch  [--config fim.yaml] [--interval 30] [--mode poll|events] [--format text|json] [--enable-response]
fim diff   <snapshot_id_1> <snapshot_id_2> [--format text|json]     # 'baseline' is also accepted as an id
fim snapshots                                                        # list stored snapshots
```

```bash
# 1. create a baseline (also writes fim.yaml if it doesn't exist, and generates the HMAC key)
python -m fim init --path /etc --path ~/.ssh --config fim.yaml

# 2. one-shot check - exit code reflects findings (cron / CI friendly)
python -m fim scan --config fim.yaml

# 3. continuous monitoring, JSON alerts for a pipeline
python -m fim watch --config fim.yaml --interval 30 --format json >> alerts.jsonl

# 4. incident timeline: what changed between two points in time?
python -m fim snapshots --config fim.yaml
python -m fim diff 20261124T182648Z 20261124T182649Z --config fim.yaml
```

**Exit codes:** `0` clean - `1` changes found - `2` at least one CRITICAL change - `3` error or
**integrity (HMAC) failure**.

See [`fim.example.yaml`](fim.example.yaml) for every config option (monitored paths with
per-path `include`/`exclude`, `hash_algorithm`, `ignore`, `critical_paths`, `state_dir`,
`key_file`, `snapshot_on_scan`, `interval`, `log_file`, `quarantine_dir`).

## Demo walkthrough

A scratch directory with a fake `etc/passwd` marked critical:

```bash
$ cat fim.yaml
paths: [demo]
critical_paths: ["**/etc/passwd"]
log_file: alerts.jsonl

$ python -m fim init --config fim.yaml
baseline created: 4 files, algorithm sha256, snapshot 20261124T182648Z
HMAC key generated: ~/.fim/fim.key  (keep it OUT of git and away from the monitored paths)

$ python -m fim scan --config fim.yaml          # nothing changed yet
scanned 4 files (0 hashed, 4 reused via mtime/size); 0 change(s)       # exit 0
```

Now simulate an intruder: append to `etc/passwd`, edit a config, delete a file, drop a script
(and leave a vim swap file, which is ignored as noise):

```bash
$ echo x >> demo/etc/passwd; echo tampered > demo/app/config.ini; rm demo/notes.txt
$ echo evil > demo/app/backdoor.sh; echo junk > demo/.config.ini.swp

$ python -m fim scan --config fim.yaml          # exit 2
2026-11-24T18:26:49Z [HIGH    ] ADDED              /demo/app/backdoor.sh  - -> 886b67480dbe
2026-11-24T18:26:49Z [MEDIUM  ] MODIFIED           /demo/app/config.ini  5891b5b522d5 -> 92e78d0b0329
2026-11-24T18:26:49Z [CRITICAL] MODIFIED           /demo/etc/passwd  8b8ab8c71d3c -> 0165150ee1d3
2026-11-24T18:26:49Z [MEDIUM  ] DELETED            /demo/notes.txt  444e0fffbd82 -> -
snapshot saved: 20261124T182649Z
scanned 4 files (3 hashed, 1 reused via mtime/size); 4 change(s)
```

Only the 3 files whose size/mtime changed were re-hashed; the `.swp` file was ignored. The same
findings as JSON (`--format json`, one object per line):

```json
{"change_type": "MODIFIED", "new_hash": "0165150e...", "old_hash": "8b8ab8c7...", "path": "/demo/etc/passwd", "severity": "CRITICAL", "timestamp": "2026-11-24T18:26:49Z"}
```

`fim diff` between the baseline snapshot and the scan snapshot reproduces the same delta (this is
how you answer "when did this change?" later), and now the attacker tries to hide by editing the
baseline directly:

```bash
$ python -m fim scan --config fim.yaml          # exit 3
!!! INTEGRITY FAILURE: baseline .fim/baseline.json failed HMAC verification - it was modified outside of fim (or the key changed)
!!! Do not trust this baseline. Investigate before re-running 'fim init'.
```

## Design notes

### Risk-based severity

Evaluated top-down, first match wins:

| # | Rule | Severity |
|---|------|----------|
| 1 | Path matches the **critical list** (any change type, including DELETED / PERMISSION_CHANGED) | `CRITICAL` |
| 2 | Permission change that *gains* setuid, setgid or world-writable | `HIGH` |
| 3 | `ADDED` / `MODIFIED` executable or script (exec bit on POSIX, or extension like `.sh .py .exe .dll .ps1 .bat .so .service`) | `HIGH` |
| 4 | Any other `MODIFIED` / `DELETED` | `MEDIUM` |
| 5 | Any other `ADDED`, any other permission change | `LOW` |

The default critical list covers `/etc/passwd`, `shadow`, `group`, `sudoers(.d)`, `sshd_config`, `hosts`,
`ld.so.preload`, cron files/directories, systemd units, any `.ssh/authorized_keys`, and on Windows the
`hosts` file, `System32\config`, scheduled-task definitions and Startup folders. Add your own with
`critical_paths:` (a leading `~` expands to the home directory). Patterns use the same gitignore-style
syntax as ignores and are matched against the absolute path. The heuristic is intentionally simple: it
demonstrates SOC-style alert prioritisation, not a perfect classifier.

### Hash algorithms: speed vs. security

| Algorithm | Notes |
|-----------|-------|
| `sha256` (default) | Strong, fast enough on modern CPUs, the sane default. |
| `sha512` | Larger digest; often as fast or faster than SHA-256 on 64-bit CPUs. |
| `md5` | Fastest, but **broken for collision resistance**. Offered only for legacy/speed scenarios. |

MD5 is weak for anything integrity-related: practical collisions mean an attacker can craft two different
files with the same digest (the same family of weakness behind finding **F-07**, a cracked MD5 password hash,
in this portfolio's Juice Shop pentest report). Use SHA-256 unless you have a specific reason not to. The
algorithm is recorded inside the signed baseline, so `scan` always uses the one the baseline was built with.

### Protecting the monitor's own state (HMAC)

A FIM that stores its baseline next to the files it watches has an obvious weakness: an attacker who modifies a
file can also "update" the baseline so the change looks normal. To address that threat model:

* On `init`, a random 256-bit key is generated (default `~/.fim/fim.key`, mode `0600`, never in the state dir, and
  excluded from git by `.gitignore`).
* The baseline and every snapshot are signed with **HMAC-SHA256** over their canonical JSON (including the
  monitored-path list and algorithm, so scope cannot be silently shrunk either).
* `scan`, `watch` (on **every** cycle) and `diff` verify the signature before trusting the file. A bad signature,
  corrupt JSON, a missing signature or a **missing key** all fail closed: loud `INTEGRITY FAILURE` message, exit code 3.
* Monitored scope comes from the signed baseline, not from `fim.yaml`, so editing the config cannot quietly stop
  something being watched. (Change scope by re-running `init --force`.)

Limits - this is a demonstration, not production key management: an attacker with root who can read the key can
re-sign a forged baseline. In real deployments keep the key on a separate account/volume/host, or in a KMS/HSM, and
ship alerts off-box. Config changes to `ignore` patterns after `init` also need a re-`init` to be consistent.

### Two-phase scanning

Hashing is the expensive part of a scan. For each file, phase 1 compares `size` and `mtime` (one `lstat`) with the
baseline; phase 2 reads and hashes only the files that differ (or are new). On a mostly-static tree this turns a full
read of every byte into a metadata walk. The status line shows the split (`3 hashed, 1 reused`).

*Documented edge case:* anyone who rewrites a file to the **same size** and **restores its mtime** evades the fast
path. A genuine content change that alters size or mtime is always caught, and a touched-but-identical file is not a
false positive (it is re-hashed and found equal). Use `--full-hash` for periodic paranoid scans that hash everything.

### Snapshots

`init` writes the baseline plus a snapshot with the same id. `fim scan` saves a signed, timestamped snapshot of the
current state **only when it finds changes** (`snapshot_on_scan: changes`, the default; `always` and `never` are also
available) - this keeps history meaningful and storage small. The baseline is not moved by a scan; use
`fim scan --update-baseline` (or `init --force`) to accept a new state. In `watch` mode a snapshot is stored when *new*
findings appear, and each distinct finding is only reported once until it disappears and recurs.

### Auto-response (opt-in)

By default fim only detects and alerts. With `--enable-response`, a file behind a `CRITICAL` ADDED / MODIFIED /
PERMISSION_CHANGED alert is moved into `quarantine_dir` (default `<state_dir>/quarantine`), and a record with the
original path, new path and reason is printed and appended to the JSON log. The quarantine directory is never itself
monitored. Because the file is moved, the next scan reports it as `DELETED` - which is the correct picture of reality.

### Platform notes

* POSIX: mode bits plus uid/gid are compared.
* Windows: simplified - mode bits (which reflect the read-only flag) and the file owner where Python can resolve it
  (3.13+). Full ACL comparison is out of scope.
* Symlinks are not followed; a link is recorded by hashing its target path. Sockets, FIFOs and devices are skipped.

## Testing

```bash
pip install -r requirements.txt
python -m pytest -q
```

107 tests build real files in `tmp_path` and assert on actual scan results. They cover: baseline creation/reload; each
of ADDED/MODIFIED/DELETED/PERMISSION_CHANGED; ignore/include patterns; the mtime/size pre-filter (including the
documented evasion edge case and `--full-hash`); HMAC tampering (edited hashes, removed entries, shrunk scope, stripped
signature, wrong/missing key, tampered snapshots, tamper-while-watching); severity for critical vs non-critical paths
and the heuristics; snapshots and `fim diff`; algorithm selection; JSON alerts and log; opt-in quarantine; watch
de-duplication; CLI exit codes and config validation. `--mode events` was smoke-tested manually with `watchdog`.

## License

MIT - see [LICENSE](LICENSE).
