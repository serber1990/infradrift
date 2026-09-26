"""
Diff engine — compares two StateSnapshots and produces a DriftReport.

Severity rules:
  CRITICAL  new listening TCP port or low UDP port, port exposed on a new address,
            new user, user uid/gid/shell changed, user added to a privileged group
  WARNING   service state or enablement changed, new enabled service, cron added/removed,
            package removed or downgraded, port closed, user removed
  INFO      package added or upgraded, new high (ephemeral-range) UDP port, new disabled service
"""
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .snapshot import StateSnapshot
from .versions import compare_versions

SEVERITIES = ('CRITICAL', 'WARNING', 'INFO')


@dataclass
class Change:
    category:    str        # packages | ports | users | groups | crons | services
    kind:        str        # added | removed | changed
    severity:    str        # CRITICAL | WARNING | INFO
    description: str        # human-readable one-liner
    detail:      str = ''   # additional context (old → new)


@dataclass
class DriftReport:
    changes:       List[Change]
    baseline_meta: Dict
    current_meta:  Dict

    @property
    def critical(self) -> List[Change]: return [c for c in self.changes if c.severity == 'CRITICAL']
    @property
    def warnings(self) -> List[Change]: return [c for c in self.changes if c.severity == 'WARNING']
    @property
    def info(self) -> List[Change]: return [c for c in self.changes if c.severity == 'INFO']
    @property
    def is_clean(self) -> bool: return not self.changes

    def has_at_least(self, severity: str) -> bool:
        rank = SEVERITIES.index(severity)
        return any(SEVERITIES.index(c.severity) <= rank for c in self.changes)

# ── Packages ──────────────────────────────────────────────────────────────────

def _diff_packages(baseline: Dict, current: Dict) -> List[Change]:
    changes = []
    for mgr in sorted(set(baseline) | set(current)):
        b, c = baseline.get(mgr, {}), current.get(mgr, {})
        for name in sorted(c.keys() - b.keys()):
            changes.append(Change('packages', 'added', 'INFO', f'[{mgr}] {name} installed', c[name]))
        for name in sorted(b.keys() - c.keys()):
            changes.append(Change('packages', 'removed', 'WARNING', f'[{mgr}] {name} removed', f'was {b[name]}'))
        for name in sorted(b.keys() & c.keys()):
            if b[name] == c[name]:
                continue
            order = compare_versions(b[name], c[name])
            if order is not None and order > 0:
                changes.append(Change('packages', 'changed', 'WARNING', f'[{mgr}] {name} downgraded',
                                      f'{b[name]} → {c[name]}'))
            else:
                changes.append(Change('packages', 'changed', 'INFO', f'[{mgr}] {name} upgraded',
                                      f'{b[name]} → {c[name]}'))
    return changes

# ── Ports ─────────────────────────────────────────────────────────────────────

def _port_key(p: Dict) -> Tuple:
    # Snapshots from infradrift 1.0 have no address: treat them as wildcard.
    return p['proto'], p.get('address', '*'), p['port']


def _port_label(p: Dict) -> str:
    addr = p.get('address', '*')
    proc = f"  ({p['process']})" if p.get('process') else ''
    return f"{p['port']}/{p['proto']} on {'all interfaces' if addr == '*' else addr}{proc}"


def _diff_ports(baseline: List[Dict], current: List[Dict], ephemeral_start: int) -> List[Change]:
    b_map = {_port_key(p): p for p in baseline}
    c_map = {_port_key(p): p for p in current}
    b_ports = {(proto, port) for proto, _, port in b_map}
    changes = []

    for key in sorted(c_map.keys() - b_map.keys(), key=lambda k: (k[0], k[2], k[1])):
        p = c_map[key]
        proto, _, port = key
        if (proto, port) in b_ports:
            changes.append(Change('ports', 'changed', 'CRITICAL',
                                  f'{_port_label(p)} — now listening on a new address'))
        elif proto == 'udp' and port >= ephemeral_start:
            changes.append(Change('ports', 'added', 'INFO', f'{_port_label(p)} — new high UDP port',
                                  'likely a client socket (ephemeral range)'))
        else:
            changes.append(Change('ports', 'added', 'CRITICAL', f'{_port_label(p)} — new listening port'))

    c_ports = {(proto, port) for proto, _, port in c_map}
    for key in sorted(b_map.keys() - c_map.keys(), key=lambda k: (k[0], k[2], k[1])):
        p = b_map[key]
        proto, _, port = key
        if (proto, port) in c_ports:
            continue   # reported as "new address" above
        severity = 'INFO' if proto == 'udp' and port >= ephemeral_start else 'WARNING'
        changes.append(Change('ports', 'removed', severity, f'{_port_label(p)} — no longer listening'))
    return changes

# ── Users and groups ──────────────────────────────────────────────────────────

def _diff_users(baseline: List[Dict], current: List[Dict]) -> List[Change]:
    b_map = {u['name']: u for u in baseline}
    c_map = {u['name']: u for u in current}
    changes = []
    for name in sorted(c_map.keys() - b_map.keys()):
        u = c_map[name]
        changes.append(Change('users', 'added', 'CRITICAL', f'{name} — new user',
                              f"uid={u['uid']} shell={u['shell']}"))
    for name in sorted(b_map.keys() - c_map.keys()):
        changes.append(Change('users', 'removed', 'WARNING', f'{name} — user removed', f"uid={b_map[name]['uid']}"))
    for name in sorted(b_map.keys() & c_map.keys()):
        b, c = b_map[name], c_map[name]
        diffs = [f'{f} {b[f]} → {c[f]}' for f in ('uid', 'gid', 'shell', 'home') if b.get(f) != c.get(f)]
        if diffs:
            changes.append(Change('users', 'changed', 'CRITICAL', f'{name} — account changed', ', '.join(diffs)))
    return changes


def _diff_groups(baseline: Dict[str, List[str]], current: Dict[str, List[str]]) -> List[Change]:
    changes = []
    for group in sorted(set(baseline) | set(current)):
        b, c = set(baseline.get(group, [])), set(current.get(group, []))
        for member in sorted(c - b):
            changes.append(Change('groups', 'added', 'CRITICAL', f'{member} added to privileged group {group}'))
        for member in sorted(b - c):
            changes.append(Change('groups', 'removed', 'WARNING', f'{member} removed from group {group}'))
    return changes

# ── Crons ─────────────────────────────────────────────────────────────────────

def _diff_crons(baseline: List[Dict], current: List[Dict]) -> List[Change]:
    b_map = {(j['schedule'], j['command']): j for j in baseline}
    c_map = {(j['schedule'], j['command']): j for j in current}
    changes = [Change('crons', 'added', 'WARNING', f'New cron job: {s}  {cmd[:80]}', c_map[(s, cmd)].get('source', ''))
               for s, cmd in sorted(c_map.keys() - b_map.keys())]
    changes += [Change('crons', 'removed', 'WARNING', f'Cron job removed: {s}  {cmd[:80]}', b_map[(s, cmd)].get('source', ''))
                for s, cmd in sorted(b_map.keys() - c_map.keys())]
    return changes

# ── Services ──────────────────────────────────────────────────────────────────

def _svc(state) -> Dict[str, str]:
    """infradrift 1.0 stored a plain state string per service."""
    return state if isinstance(state, dict) else {'active': str(state), 'enabled': ''}


def _diff_services(baseline: Dict, current: Dict) -> List[Change]:
    changes = []
    for svc in sorted(set(baseline) | set(current)):
        if svc not in baseline:
            c = _svc(current[svc])
            severity = 'WARNING' if c.get('enabled') == 'enabled' or c.get('active') == 'active' else 'INFO'
            changes.append(Change('services', 'added', severity, f'{svc} — new service',
                                  f"{c.get('active')}, {c.get('enabled') or 'unknown'}"))
            continue
        if svc not in current:
            changes.append(Change('services', 'removed', 'WARNING', f'{svc} — service no longer present'))
            continue
        b, c = _svc(baseline[svc]), _svc(current[svc])
        if b.get('active') != c.get('active'):
            changes.append(Change('services', 'changed', 'WARNING', f'{svc}  {b.get("active")} → {c.get("active")}'))
        if b.get('enabled') and c.get('enabled') and b['enabled'] != c['enabled']:
            changes.append(Change('services', 'changed', 'WARNING',
                                  f'{svc}  {b["enabled"]} → {c["enabled"]}', 'boot-time enablement changed'))
    return changes

# ── Entry point ───────────────────────────────────────────────────────────────

def diff_snapshots(baseline: StateSnapshot, current: StateSnapshot) -> DriftReport:
    ephemeral = int(current.meta.get('ephemeral_port_start') or 32768)
    changes: List[Change] = []
    changes += _diff_packages(baseline.packages, current.packages)
    changes += _diff_ports(baseline.ports, current.ports, ephemeral)
    changes += _diff_users(baseline.users, current.users)
    changes += _diff_groups(baseline.groups, current.groups)
    changes += _diff_crons(baseline.crons, current.crons)
    changes += _diff_services(baseline.services, current.services)

    order = {s: i for i, s in enumerate(SEVERITIES)}
    changes.sort(key=lambda c: (order.get(c.severity, 3), c.category, c.description))
    return DriftReport(changes=changes, baseline_meta=baseline.meta, current_meta=current.meta)
