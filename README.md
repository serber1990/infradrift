# infradrift

[![CI](https://github.com/serber1990/infradrift/actions/workflows/ci.yml/badge.svg)](https://github.com/serber1990/infradrift/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/infradrift.svg)](https://badge.fury.io/py/infradrift)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Detect **infrastructure drift** between a known-good baseline and the current state of any Linux server —
packages, listening ports, user accounts, privileged groups, cron jobs and systemd services.

Take a snapshot when the server is in a good state. Run `check` any time — after a deploy, from cron,
or during an incident — to see exactly what changed. No agent, no daemon, no dependencies on the server
beyond Python.

---

## 📄 Example

```
  ╔═══════════════════════════════╗
  ║  infradrift  ·  drift report  ║
  ╚═══════════════════════════════╝

  Baseline   2026-05-10T09:00:00+02:00  (prod-01)  as root
  Current    2026-05-12T14:22:18+02:00  (prod-01)  as root


  ── Ports ─────────────────────────────────
  ⛔ +  4444/tcp on all interfaces  (nc) — new listening port
  ⛔ ~  6379/tcp on all interfaces  (redis-server) — now listening on a new address

  ── Users ─────────────────────────────────
  ⛔ ~  backup — account changed  shell /usr/sbin/nologin → /bin/bash
  ⛔ +  deploy — new user  uid=1005 shell=/bin/bash

  ── Privileged Groups ─────────────────────
  ⛔ +  deploy added to privileged group sudo

  ── Cron Jobs ─────────────────────────────
  ⚠  +  New cron job: @reboot  /tmp/.cache/update.sh  crontab:www-data

  ── Services ──────────────────────────────
  ⚠  ~  nginx  active → failed

  ── Packages ──────────────────────────────
  · ~  [apt] openssl upgraded  3.0.13-0ubuntu3 → 3.0.13-0ubuntu3.1

  ──────────────────────────────────────────
  8 changes detected  (5 critical, 2 warnings, 1 info)
```

---

## ✨ What it detects

| Category | What's tracked |
|----------|----------------|
| **Packages** | dpkg (Debian/Ubuntu), rpm (RHEL/Fedora/SUSE), pacman (Arch), pip — installed, removed, upgraded, downgraded |
| **Ports** | Listening TCP and bound UDP sockets **with their bind address** — a service moving from `127.0.0.1` to `0.0.0.0` is flagged |
| **Users** | `/etc/passwd` accounts — added, removed, uid/gid/shell/home changes |
| **Privileged groups** | Membership of `sudo`, `wheel`, `admin`, `docker`, `lxd`, `libvirt`, `adm`, `disk`, `shadow`, `root` |
| **Cron jobs** | User crontabs, `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, including `@reboot` entries |
| **Services** | systemd unit state (active / inactive / failed) and boot enablement (enabled / disabled / masked) |

### Severity levels

| Severity | Examples |
|----------|----------|
| ⛔ **CRITICAL** | New listening port, port exposed on a new address, new user, uid/shell change, user added to a privileged group |
| ⚠️ **WARNING** | Service state or enablement change, new enabled service, cron job added/removed, package removed or downgraded |
| ℹ️ **INFO** | Package installed or upgraded, new high UDP port (ephemeral range — usually a client socket) |

---

## 📥 Installation

```bash
pip install infradrift
```

Run it as **root** for complete results: other users' crontabs and the process names of every socket are
only visible to root. infradrift warns you when it runs unprivileged.

---

## 🛠 Usage

### 1 — Take a baseline snapshot

```bash
sudo infradrift snapshot
```

Saved to `/var/lib/infradrift/baseline.json` when run as root, or `~/.config/infradrift/baseline.json` otherwise.
The file is created with `0600` permissions: it lists users, ports and cron commands.

```bash
sudo infradrift snapshot --output /opt/baselines/prod-$(date +%F).json
```

### 2 — Check for drift

```bash
sudo infradrift check                                   # terminal report
sudo infradrift check --format json | jq .summary       # JSON on stdout, progress on stderr
sudo infradrift check -f markdown -o drift-report.md    # Markdown file
sudo infradrift check --baseline /opt/baselines/prod-2026-05-12.json --fail-on critical
```

### 3 — Diff any two snapshots

```bash
infradrift diff before-deploy.json after-deploy.json
infradrift diff web-01.json web-02.json --format markdown   # compare two servers
```

---

## 🔁 Use in cron / CI

| Exit code | Meaning |
|-----------|---------|
| `0` | No drift at or above `--fail-on` |
| `1` | Drift detected |
| `2` | Error (missing or unreadable baseline) |

```cron
# Every hour: keep a Markdown report only when something critical changed
0 * * * * root infradrift check --fail-on critical -o /var/log/infradrift/last.md || cp /var/log/infradrift/last.md /var/log/infradrift/alert-$(date +\%F-\%H).md
```

---

## 📋 Options

### `infradrift snapshot`
| Option | Description |
|--------|-------------|
| `-o`, `--output FILE` | Where to save the baseline |

### `infradrift check` / `infradrift diff BASELINE CURRENT`
| Option | Description |
|--------|-------------|
| `-b`, `--baseline FILE` | *(check)* Baseline to compare against |
| `-f`, `--format` | `terminal` (default), `json` or `markdown` |
| `-o`, `--output FILE` | Write the report to a file (JSON or Markdown) |
| `--fail-on LEVEL` | `info` (default: any change), `warning`, `critical` or `never` |

---

## 🧪 Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

See [CHANGELOG.md](CHANGELOG.md) for release notes.

---

## 📝 License

MIT — see [LICENSE](LICENSE).

## 🌐 Connect

[![GitHub](https://img.shields.io/badge/GitHub-@serber1990-181717?style=flat-square&logo=github)](https://github.com/serber1990)
