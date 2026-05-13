"""
Diff engine — compares two StateSnapshots and produces a DriftReport.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .snapshot import StateSnapshot


# ── Change model ──────────────────────────────────────────────────────────────

@dataclass
class Change:
    category:    str        # packages | ports | users | crons | services
    kind:        str        # added | removed | changed
    severity:    str        # CRITICAL | WARNING | INFO
    description: str        # human-readable one-liner
    detail:      str = ''   # additional context (old → new)


@dataclass
class DriftReport:
    changes:      List[Change]
    baseline_meta: Dict
    current_meta:  Dict

    @property
    def critical(self)  -> List[Change]: return [c for c in self.changes if c.severity == 'CRITICAL']
    @property
    def warnings(self)  -> List[Change]: return [c for c in self.changes if c.severity == 'WARNING']
    @property
    def info(self)      -> List[Change]: return [c for c in self.changes if c.severity == 'INFO']
    @property
    def is_clean(self)  -> bool: return not self.changes


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sev(cat: str, kind: str) -> str:
    """Assign severity based on category + change type."""
    matrix = {
        # (category, kind) → severity
        ('ports',    'added'):   'CRITICAL',
        ('users',    'added'):   'CRITICAL',
        ('users',    'changed'): 'CRITICAL',   # uid/shell change = suspicious
        ('services', 'added'):   'WARNING',
        ('services', 'removed'): 'WARNING',
        ('services', 'changed'): 'WARNING',
        ('crons',    'added'):   'WARNING',
        ('crons',    'removed'): 'WARNING',
        ('packages', 'removed'): 'WARNING',
        ('ports',    'removed'): 'WARNING',
        ('users',    'removed'): 'WARNING',
        ('packages', 'added'):   'INFO',
        ('packages', 'changed'): 'INFO',       # version bump
    }
    return matrix.get((cat, kind), 'INFO')


# ── Category diffing ──────────────────────────────────────────────────────────

def _diff_packages(baseline: Dict, current: Dict) -> List[Change]:
    changes = []
    all_managers = set(baseline) | set(current)

    for mgr in sorted(all_managers):
        b_pkgs = baseline.get(mgr, {})
        c_pkgs = current.get(mgr, {})
        all_names = set(b_pkgs) | set(c_pkgs)

        for name in sorted(all_names):
            if name not in b_pkgs:
                changes.append(Change(
                    category='packages', kind='added',
                    severity=_sev('packages', 'added'),
                    description=f'[{mgr}] {name}  added  ({c_pkgs[name]})',
                ))
            elif name not in c_pkgs:
                changes.append(Change(
                    category='packages', kind='removed',
                    severity=_sev('packages', 'removed'),
                    description=f'[{mgr}] {name}  removed',
                    detail=f'was {b_pkgs[name]}',
                ))
            elif b_pkgs[name] != c_pkgs[name]:
                changes.append(Change(
                    category='packages', kind='changed',
                    severity=_sev('packages', 'changed'),
                    description=f'[{mgr}] {name}  {b_pkgs[name]}  →  {c_pkgs[name]}',
                ))
    return changes


def _port_key(p: Dict) -> Tuple:
    return (p['port'], p['proto'])


def _diff_ports(baseline: List[Dict], current: List[Dict]) -> List[Change]:
    b_map = {_port_key(p): p for p in baseline}
    c_map = {_port_key(p): p for p in current}
    changes = []

    for key in sorted(set(c_map) - set(b_map)):
        p = c_map[key]
        changes.append(Change(
            category='ports', kind='added',
            severity=_sev('ports', 'added'),
            description=f'{p["port"]}/{p["proto"]}  {p["state"]}  {p["process"]}  — new listening port',
        ))

    for key in sorted(set(b_map) - set(c_map)):
        p = b_map[key]
        changes.append(Change(
            category='ports', kind='removed',
            severity=_sev('ports', 'removed'),
            description=f'{p["port"]}/{p["proto"]}  {p["process"]}  — port no longer listening',
        ))

    return changes


def _diff_users(baseline: List[Dict], current: List[Dict]) -> List[Change]:
    b_map = {u['name']: u for u in baseline}
    c_map = {u['name']: u for u in current}
    changes = []

    for name in sorted(set(c_map) - set(b_map)):
        u = c_map[name]
        changes.append(Change(
            category='users', kind='added',
            severity=_sev('users', 'added'),
            description=f'{name}  uid={u["uid"]}  {u["shell"]}  — new user',
        ))

    for name in sorted(set(b_map) - set(c_map)):
        u = b_map[name]
        changes.append(Change(
            category='users', kind='removed',
            severity=_sev('users', 'removed'),
            description=f'{name}  uid={u["uid"]}  — user removed',
        ))

    for name in sorted(set(b_map) & set(c_map)):
        b, c = b_map[name], c_map[name]
        diffs = []
        if b['uid'] != c['uid']:
            diffs.append(f'uid {b["uid"]} → {c["uid"]}')
        if b['shell'] != c['shell']:
            diffs.append(f'shell {b["shell"]} → {c["shell"]}')
        if b['gid'] != c['gid']:
            diffs.append(f'gid {b["gid"]} → {c["gid"]}')
        if diffs:
            changes.append(Change(
                category='users', kind='changed',
                severity=_sev('users', 'changed'),
                description=f'{name}  — user attributes changed',
                detail=', '.join(diffs),
            ))

    return changes


def _cron_key(c: Dict) -> Tuple:
    return (c['schedule'], c['command'][:80])


def _diff_crons(baseline: List[Dict], current: List[Dict]) -> List[Change]:
    b_keys = {_cron_key(c) for c in baseline}
    c_keys = {_cron_key(c) for c in current}
    changes = []

    for key in sorted(c_keys - b_keys):
        changes.append(Change(
            category='crons', kind='added',
            severity=_sev('crons', 'added'),
            description=f'New cron job: {key[0]}  {key[1][:60]}',
        ))

    for key in sorted(b_keys - c_keys):
        changes.append(Change(
            category='crons', kind='removed',
            severity=_sev('crons', 'removed'),
            description=f'Removed cron job: {key[0]}  {key[1][:60]}',
        ))

    return changes


def _diff_services(baseline: Dict[str, str], current: Dict[str, str]) -> List[Change]:
    changes = []
    all_svcs = set(baseline) | set(current)

    for svc in sorted(all_svcs):
        b_state = baseline.get(svc)
        c_state = current.get(svc)

        if b_state is None:
            changes.append(Change(
                category='services', kind='added',
                severity=_sev('services', 'added'),
                description=f'{svc}  — new service ({c_state})',
            ))
        elif c_state is None:
            changes.append(Change(
                category='services', kind='removed',
                severity=_sev('services', 'removed'),
                description=f'{svc}  — service no longer present (was {b_state})',
            ))
        elif b_state != c_state:
            changes.append(Change(
                category='services', kind='changed',
                severity=_sev('services', 'changed'),
                description=f'{svc}  {b_state}  →  {c_state}',
            ))

    return changes


# ── Main diff entry point ─────────────────────────────────────────────────────

def diff_snapshots(baseline: StateSnapshot, current: StateSnapshot) -> DriftReport:
    changes: List[Change] = []
    changes.extend(_diff_packages(baseline.packages, current.packages))
    changes.extend(_diff_ports(baseline.ports, current.ports))
    changes.extend(_diff_users(baseline.users, current.users))
    changes.extend(_diff_crons(baseline.crons, current.crons))
    changes.extend(_diff_services(baseline.services, current.services))

    # Sort: CRITICAL first, then WARNING, then INFO
    order = {'CRITICAL': 0, 'WARNING': 1, 'INFO': 2}
    changes.sort(key=lambda c: (order.get(c.severity, 3), c.category, c.description))

    return DriftReport(
        changes=changes,
        baseline_meta=baseline.meta,
        current_meta=current.meta,
    )
