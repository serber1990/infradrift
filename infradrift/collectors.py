"""
State collectors — each returns plain dicts/lists that can be JSON-serialised.
Every collector degrades gracefully when a tool is unavailable or a file is unreadable.
Run as root for complete results (other users' crontabs, process names of all sockets).
"""
import json
import os
import platform
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _run(cmd: list, timeout: int = 60) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ''
    return r.stdout


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(errors='replace')
    except OSError:
        return None

# ── Packages ──────────────────────────────────────────────────────────────────

def _parse_pairs(out: str, sep: Optional[str] = '\t') -> Dict[str, str]:
    pkgs = {}
    for line in out.splitlines():
        parts = line.split(sep, 1)
        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
            pkgs[parts[0].strip()] = parts[1].strip()
    return pkgs


def collect_packages() -> Dict[str, Dict[str, str]]:
    """
    Returns {'apt': {pkg: version}, 'rpm': {…}, 'pacman': {…}, 'pip': {…}}.
    Only the package managers present on the system are included.
    """
    result: Dict[str, Dict[str, str]] = {}

    # dpkg (Debian/Ubuntu): only fully installed packages ("ii"), arch-qualified names
    out = _run(['dpkg-query', '-W', '-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n'])
    if out:
        pkgs = {}
        for line in out.splitlines():
            parts = line.split('\t')
            if len(parts) == 3 and parts[0].startswith('ii') and parts[2]:
                pkgs[parts[1]] = parts[2]
        if pkgs:
            result['apt'] = pkgs

    # rpm (RHEL/Fedora/SUSE)
    pkgs = _parse_pairs(_run(['rpm', '-qa', '--queryformat', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n']))
    if pkgs:
        result['rpm'] = {k: v[2:] if v.startswith('0:') else v for k, v in pkgs.items()}

    # pacman (Arch and derivatives)
    pkgs = _parse_pairs(_run(['pacman', '-Q']), sep=' ')
    if pkgs:
        result['pacman'] = pkgs

    # pip (system Python)
    out = _run(['python3', '-m', 'pip', 'list', '--format=json', '--disable-pip-version-check'])
    try:
        pip = {p['name'].lower(): p['version'] for p in json.loads(out)}
        if pip:
            result['pip'] = pip
    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    return result

# ── Ports ─────────────────────────────────────────────────────────────────────

_WILDCARDS = {'0.0.0.0', '*', '[::]', '::', '[::ffff:0.0.0.0]'}


def _split_addr(local: str) -> Optional[Tuple[str, int]]:
    """'0.0.0.0:22' → ('*', 22); '[::1]:631' → ('[::1]', 631); '127.0.0.53%lo:53' → ('127.0.0.53%lo', 53)."""
    m = re.match(r'^(.*):(\d+)$', local)
    if not m:
        return None
    addr = m.group(1)
    return ('*' if addr in _WILDCARDS else addr), int(m.group(2))


def ephemeral_port_start() -> int:
    text = _read(Path('/proc/sys/net/ipv4/ip_local_port_range'))
    try:
        return int(text.split()[0]) if text else 32768
    except (ValueError, IndexError):
        return 32768


def parse_ss(out: str) -> List[Dict]:
    """Parse `ss -tulnp` output: Netid State Recv-Q Send-Q Local Peer [Process]."""
    ports = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] in ('Netid', 'State'):
            continue
        proto = parts[0].lower()
        if proto not in ('tcp', 'udp'):
            continue
        parsed = _split_addr(parts[4])
        if not parsed:
            continue
        pm = re.search(r'users:\(\("([^"]+)"', line)
        ports.append({'proto': proto, 'address': parsed[0], 'port': parsed[1],
                      'state': parts[1], 'process': pm.group(1) if pm else ''})
    return ports


def parse_netstat(out: str) -> List[Dict]:
    """Parse `netstat -tulnp` output (fallback when `ss` is missing)."""
    ports = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[0].startswith(('tcp', 'udp')):
            continue
        proto = parts[0].rstrip('6')
        if proto == 'tcp' and 'LISTEN' not in line:
            continue
        parsed = _split_addr(parts[3])
        if not parsed:
            continue
        pm = re.search(r'\s\d+/([^\s:]+)', line)   # "812/sshd", "99/nginx: master"
        proc = pm.group(1) if pm else ''
        ports.append({'proto': proto, 'address': parsed[0], 'port': parsed[1],
                      'state': 'LISTEN' if proto == 'tcp' else 'UNCONN', 'process': proc})
    return ports


def collect_ports() -> List[Dict]:
    """Listening TCP sockets and bound UDP sockets, with bind address and process."""
    out = _run(['ss', '-tulnp'])
    ports = parse_ss(out) if out else parse_netstat(_run(['netstat', '-tulnp']))
    # One entry per (proto, address, port): IPv4/IPv6 twins and SO_REUSEPORT copies collapse.
    unique = {(p['proto'], p['address'], p['port']): p for p in ports}
    return [unique[k] for k in sorted(unique, key=lambda k: (k[0], k[2], k[1]))]

# ── Users and privileged groups ───────────────────────────────────────────────

PRIVILEGED_GROUPS = ('root', 'sudo', 'wheel', 'admin', 'adm', 'docker', 'lxd', 'libvirt', 'disk', 'shadow')


def parse_passwd(text: str) -> List[Dict]:
    users = []
    for line in text.splitlines():
        parts = line.split(':')
        if len(parts) < 7 or line.startswith('#'):
            continue
        name, _, uid, gid, _gecos, home, shell = parts[:7]
        try:
            users.append({'name': name, 'uid': int(uid), 'gid': int(gid), 'home': home, 'shell': shell})
        except ValueError:
            continue
    return users


def collect_users() -> List[Dict]:
    """All accounts from /etc/passwd except nobody-style ids (≥ 65534)."""
    text = _read(Path('/etc/passwd')) or ''
    return [u for u in parse_passwd(text) if u['uid'] < 65534]


def collect_groups() -> Dict[str, List[str]]:
    """Members of privileged groups (sudo, wheel, docker…) from /etc/group."""
    groups = {}
    for line in (_read(Path('/etc/group')) or '').splitlines():
        parts = line.split(':')
        if len(parts) >= 4 and parts[0] in PRIVILEGED_GROUPS:
            groups[parts[0]] = sorted(m for m in parts[3].split(',') if m)
    return groups

# ── Cron jobs ─────────────────────────────────────────────────────────────────

_CRON_LINE_RE = re.compile(r'^(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$')


def parse_cron(text: str, source: str) -> List[Dict]:
    """Parse crontab text, including @reboot/@daily entries; variable lines are skipped."""
    jobs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
            continue
        m = _CRON_LINE_RE.match(line)
        if m:
            jobs.append({'schedule': m.group(1), 'command': m.group(2).strip(), 'source': source})
    return jobs


def collect_crons() -> List[Dict]:
    """Cron jobs from user crontabs, /etc/crontab, /etc/cron.d and the /etc/cron.<period> directories."""
    jobs: List[Dict] = []

    # Per-user crontabs: the spool is only readable by root; otherwise ask crontab for ours.
    spools = [Path('/var/spool/cron/crontabs'), Path('/var/spool/cron')]
    read_spool = False
    for spool in spools:
        if spool.is_dir() and os.access(spool, os.R_OK | os.X_OK):
            for f in sorted(spool.iterdir()):
                text = _read(f) if f.is_file() else None
                if text is not None:
                    jobs.extend(parse_cron(text, f'crontab:{f.name}'))
                    read_spool = True
    if not read_spool:
        out = _run(['crontab', '-l'])
        if out:
            jobs.extend(parse_cron(out, f"crontab:{os.environ.get('USER', 'user')}"))

    text = _read(Path('/etc/crontab'))
    if text:
        jobs.extend(parse_cron(text, '/etc/crontab'))

    cron_d = Path('/etc/cron.d')
    if cron_d.is_dir():
        for f in sorted(cron_d.iterdir()):
            if f.is_file() and not f.name.startswith('.'):
                jobs.extend(parse_cron(_read(f) or '', str(f)))

    for period in ('hourly', 'daily', 'weekly', 'monthly'):
        d = Path(f'/etc/cron.{period}')
        if d.is_dir():
            for f in sorted(d.iterdir()):
                if f.is_file() and not f.name.startswith('.') and f.name != 'placeholder':
                    jobs.append({'schedule': f'@{period}', 'command': str(f), 'source': str(d)})

    unique = {}
    for j in jobs:
        unique.setdefault((j['schedule'], j['command']), j)
    return list(unique.values())

# ── Services ──────────────────────────────────────────────────────────────────

def parse_systemd(units_out: str, files_out: str) -> Dict[str, Dict[str, str]]:
    """Merge `systemctl list-units` (active state) and `list-unit-files` (enablement)."""
    services: Dict[str, Dict[str, str]] = {}
    for line in units_out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].endswith('.service'):
            services[parts[0].removesuffix('.service')] = {'active': parts[2], 'enabled': ''}
    for line in files_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith('.service') and '@.' not in parts[0]:
            name = parts[0].removesuffix('.service')
            services.setdefault(name, {'active': 'inactive', 'enabled': ''})['enabled'] = parts[1]
    return services


def collect_services() -> Dict[str, Dict[str, str]]:
    """{service: {'active': 'active|inactive|failed…', 'enabled': 'enabled|disabled|static|masked…'}}"""
    units = _run(['systemctl', 'list-units', '--type=service', '--all', '--plain', '--no-legend', '--no-pager'])
    if units:
        files = _run(['systemctl', 'list-unit-files', '--type=service', '--plain', '--no-legend', '--no-pager'])
        return parse_systemd(units, files)

    services = {}
    for line in _run(['service', '--status-all']).splitlines():   # sysvinit fallback
        m = re.search(r'\[\s*([+\-?])\s*\]\s+(\S+)', line)
        if m:
            services[m.group(2)] = {'active': 'active' if m.group(1) == '+' else 'inactive', 'enabled': ''}
    return services

# ── System metadata ───────────────────────────────────────────────────────────

def collect_meta() -> Dict[str, str]:
    os_desc = ''
    for line in (_read(Path('/etc/os-release')) or '').splitlines():
        if line.startswith('PRETTY_NAME='):
            os_desc = line.split('=', 1)[1].strip().strip('"')
            break
    return {
        'hostname': _run(['hostname', '-f']).strip() or platform.node(),
        'captured_at': datetime.now().astimezone().isoformat(timespec='seconds'),
        'os': os_desc or platform.platform(),
        'kernel': platform.release(),
        'user': 'root' if os.geteuid() == 0 else os.environ.get('USER', str(os.geteuid())),
        'ephemeral_port_start': ephemeral_port_start(),
    }
