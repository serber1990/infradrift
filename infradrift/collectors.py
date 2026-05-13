"""
State collectors — each returns a plain dict/list that can be JSON-serialised.
Every collector degrades gracefully when a tool is unavailable.
"""
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


def _run(cmd: list, timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return ''


# ── Packages ──────────────────────────────────────────────────────────────────

def collect_packages() -> Dict[str, Dict[str, str]]:
    """
    Returns {'apt': {pkg: version}, 'rpm': {…}, 'pip': {…}}
    Only the managers found on the system are included.
    """
    result: Dict[str, Dict[str, str]] = {}

    # dpkg (Debian/Ubuntu)
    out = _run(['dpkg-query', '-W', '-f=${Package}\t${Version}\n'])
    if out:
        pkgs = {}
        for line in out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) == 2 and parts[1].strip():
                pkgs[parts[0].strip()] = parts[1].strip()
        if pkgs:
            result['apt'] = pkgs

    # rpm (RHEL/CentOS/Fedora)
    out = _run(['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\n'])
    if out:
        pkgs = {}
        for line in out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) == 2:
                pkgs[parts[0].strip()] = parts[1].strip()
        if pkgs:
            result['rpm'] = pkgs

    # pip (Python)
    out = _run(['pip3', 'list', '--format=json'])
    if not out:
        out = _run(['pip', 'list', '--format=json'])
    if out:
        try:
            pip_list = json.loads(out)
            result['pip'] = {p['name']: p['version'] for p in pip_list}
        except (json.JSONDecodeError, KeyError):
            pass

    return result


# ── Ports ─────────────────────────────────────────────────────────────────────

def collect_ports() -> List[Dict]:
    """
    Returns list of {port, proto, state, process} for listening sockets.
    Uses `ss` first, falls back to `netstat`.
    """
    ports = []

    # ss -tlunp  (preferred)
    out = _run(['ss', '-tlunp'])
    if out:
        for line in out.splitlines()[1:]:   # skip header
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[0]
            local = parts[4]                # e.g. 0.0.0.0:22 or *:80
            proto = 'tcp' if line.startswith('tcp') or line.startswith('TCP') else 'udp'

            # Extract port from address
            m = re.search(r':(\d+)$', local)
            if not m:
                continue
            port = int(m.group(1))

            # Extract process name from users:(("nginx",pid=...,fd=...))
            proc = ''
            pm = re.search(r'users:\(\("([^"]+)"', line)
            if pm:
                proc = pm.group(1)

            ports.append({'port': port, 'proto': proto, 'state': state, 'process': proc})
        return ports

    # netstat fallback
    out = _run(['netstat', '-tlunp'])
    if out:
        for line in out.splitlines():
            if 'LISTEN' not in line and 'UNCONN' not in line:
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0].lower().rstrip('6')  # tcp6 → tcp
            local = parts[3]
            m = re.search(r':(\d+)$', local)
            if not m:
                continue
            port = int(m.group(1))
            proc = parts[-1].split('/')[-1] if '/' in parts[-1] else ''
            state = 'LISTEN'
            ports.append({'port': port, 'proto': proto, 'state': state, 'process': proc})

    return ports


# ── Users ─────────────────────────────────────────────────────────────────────

def collect_users() -> List[Dict]:
    """
    Parse /etc/passwd and return all non-nologin users plus service accounts.
    Excludes uid 65534 (nobody) and above.
    """
    users = []
    try:
        for line in Path('/etc/passwd').read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 7:
                continue
            name, _, uid, gid, gecos, home, shell = parts[:7]
            try:
                uid_i = int(uid)
                gid_i = int(gid)
            except ValueError:
                continue
            if uid_i >= 65534:
                continue
            users.append({
                'name': name,
                'uid': uid_i,
                'gid': gid_i,
                'home': home,
                'shell': shell,
            })
    except (PermissionError, FileNotFoundError):
        pass
    return users


# ── Cron jobs ─────────────────────────────────────────────────────────────────

_CRON_LINE_RE = re.compile(
    r'^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$'
)


def _parse_cron_lines(text: str, source: str) -> List[Dict]:
    jobs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('@'):
            continue
        # Skip variable assignments
        if re.match(r'^[A-Z_]+=', line):
            continue
        m = _CRON_LINE_RE.match(line)
        if m:
            jobs.append({
                'schedule': m.group(1),
                'command': m.group(2).strip(),
                'source': source,
            })
    return jobs


def collect_crons() -> List[Dict]:
    """Collect cron jobs from user crontabs and /etc/cron.d."""
    jobs = []

    # Current user crontab
    out = _run(['crontab', '-l'])
    if out and 'no crontab' not in out.lower():
        jobs.extend(_parse_cron_lines(out, 'crontab:user'))

    # Root crontab (if we can read it)
    out = _run(['sudo', '-n', 'crontab', '-l', '-u', 'root'])
    if out and 'no crontab' not in out.lower() and 'sudo' not in out.lower():
        jobs.extend(_parse_cron_lines(out, 'crontab:root'))

    # /etc/crontab
    try:
        text = Path('/etc/crontab').read_text(errors='replace')
        jobs.extend(_parse_cron_lines(text, '/etc/crontab'))
    except (PermissionError, FileNotFoundError):
        pass

    # /etc/cron.d/*
    cron_d = Path('/etc/cron.d')
    if cron_d.is_dir():
        for f in sorted(cron_d.iterdir()):
            if f.is_file() and not f.name.startswith('.'):
                try:
                    text = f.read_text(errors='replace')
                    jobs.extend(_parse_cron_lines(text, str(f)))
                except PermissionError:
                    pass

    # Deduplicate by (schedule, command)
    seen = set()
    unique = []
    for j in jobs:
        key = (j['schedule'], j['command'])
        if key not in seen:
            seen.add(key)
            unique.append(j)

    return unique


# ── Services ──────────────────────────────────────────────────────────────────

def collect_services() -> Dict[str, str]:
    """
    Returns {service_name: state} for all systemd service units.
    Falls back to sysvinit `service --status-all` output.
    """
    services: Dict[str, str] = {}

    # systemctl
    out = _run([
        'systemctl', 'list-units', '--type=service',
        '--no-pager', '--plain', '--no-legend',
        '--all',
    ])
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            unit = parts[0].removesuffix('.service')
            state = parts[3]  # 'active', 'inactive', 'failed', etc.
            services[unit] = state
        return services

    # sysvinit fallback
    out = _run(['service', '--status-all'])
    for line in out.splitlines():
        m = re.search(r'\[\s*([+\-?])\s*\]\s+(\S+)', line)
        if m:
            state_char = m.group(1)
            name = m.group(2)
            services[name] = 'active' if state_char == '+' else 'inactive'

    return services


# ── System metadata ───────────────────────────────────────────────────────────

def collect_meta() -> Dict[str, str]:
    import platform
    from datetime import datetime

    hostname = _run(['hostname', '-f']).strip() or platform.node()
    kernel = _run(['uname', '-r']).strip()

    # OS description
    os_desc = ''
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if line.startswith('PRETTY_NAME='):
                os_desc = line.split('=', 1)[1].strip('"')
                break
    except FileNotFoundError:
        os_desc = platform.platform()

    return {
        'hostname': hostname,
        'captured_at': datetime.now().isoformat(timespec='seconds'),
        'os': os_desc,
        'kernel': kernel,
    }
