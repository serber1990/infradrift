# infradrift

[![PyPI version](https://badge.fury.io/py/infradrift.svg)](https://badge.fury.io/py/infradrift)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Detect **infrastructure drift** between a known-good baseline and the current state of any Linux server — packages, open ports, user accounts, cron jobs, and systemd services.

Take a snapshot when the server is in a good state. Run `check` anytime to see exactly what changed.

---

## ✨ What it detects

| Category | What's tracked |
|----------|----------------|
| **Packages** | dpkg (Debian/Ubuntu), rpm (RHEL/CentOS), pip (Python) — added, removed, upgraded |
| **Ports** | All TCP/UDP listening ports and their bound processes |
| **Users** | `/etc/passwd` accounts — added, removed, UID/shell changes |
| **Cron jobs** | Per-user crontabs and `/etc/cron.d/` entries |
| **Services** | Systemd unit state — started, stopped, enabled/disabled changes |

### Severity levels

| Severity | Examples |
|----------|----------|
| ⛔ **CRITICAL** | New listening port, new user account, UID changed to 0, shell changed |
| ⚠️ **WARNING** | Service state change, cron added/removed, package removed |
| ℹ️ **INFO** | Package added or upgraded |

---

## 📥 Installation

```bash
pip install infradrift
```

---

## 🛠 Usage

### 1 — Take a baseline snapshot

```bash
infradrift snapshot
```

Saves to `/var/lib/infradrift/baseline.json` by default (falls back to `~/.infradrift/baseline.json`).

```bash
# Custom path
infradrift snapshot --output /opt/baselines/prod-2026-05-12.json
```

### 2 — Check for drift

```bash
infradrift check
```

```bash
# JSON output (for scripts/CI)
infradrift check --format json

# Markdown report to file
infradrift check --format markdown --output drift-report.md

# Custom baseline path
infradrift check --baseline /opt/baselines/prod-2026-05-12.json
```

### 3 — Diff any two snapshots

```bash
infradrift diff baseline.json current.json
infradrift diff snap_before_deploy.json snap_after_deploy.json --format markdown
```

---

## 📋 Options

### `infradrift snapshot`
| Option | Description |
|--------|-------------|
| `--output FILE` | Where to save the baseline (default: `/var/lib/infradrift/baseline.json`) |

### `infradrift check`
| Option | Description |
|--------|-------------|
| `--baseline FILE` | Baseline to compare against (default: `/var/lib/infradrift/baseline.json`) |
| `--format` | `terminal` (default), `json`, or `markdown` |
| `--output FILE` | Save report to file (markdown format only) |

### `infradrift diff`
| Option | Description |
|--------|-------------|
| `BASELINE` | First snapshot file |
| `CURRENT` | Second snapshot file |
| `--format` | `terminal` (default), `json`, or `markdown` |
| `--output FILE` | Save report to file (markdown format only) |

---

## 📄 Example output

```
  ╔══════════════════════════════════════╗
  ║  infradrift  ·  drift report         ║
  ╚══════════════════════════════════════╝

  Baseline   2026-05-10 09:00:01  (prod-server-01)
  Current    2026-05-12 14:22:18  (prod-server-01)

  ── Ports ──────────────────────────────
  ⛔ +  New port 4444/tcp (nc)
  ⚠  -  Port 8080/tcp removed (old-api)

  ── Users ──────────────────────────────
  ⛔ +  New user: deploy (uid=1005)
  ⛔ ~  User backup: shell changed /bin/false → /bin/bash

  ── Services ───────────────────────────
  ⚠  ~  nginx: active → failed
  ⚠  +  new-daemon.service: enabled (dead)

  ──────────────────────────────────────────
  5 changes detected  (2 critical, 3 warnings)
```

---

## 🔁 Use in CI / cron

```bash
# Exit code 0 = clean, exit code 1 = drift detected
infradrift check --format json | jq '.summary'
```

```cron
# Check every hour, save report on drift
0 * * * * infradrift check --format markdown --output /var/log/infradrift-$(date +\%F-\%H).md
```

---

## 📝 License

MIT — see [LICENSE](LICENSE).

## 🌐 Connect

[![GitHub](https://img.shields.io/badge/GitHub-@serber1990-181717?style=flat-square&logo=github)](https://github.com/serber1990)
