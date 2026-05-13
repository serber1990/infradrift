"""
StateSnapshot — captures and persists full server state.
"""
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .collectors import (
    collect_meta, collect_packages, collect_ports,
    collect_users, collect_crons, collect_services,
)

VERSION = "1.0.0"
DEFAULT_PATH = Path.home() / '.config' / 'infradrift' / 'baseline.json'


@dataclass
class StateSnapshot:
    meta:     Dict
    packages: Dict[str, Dict[str, str]]
    ports:    List[Dict]
    users:    List[Dict]
    crons:    List[Dict]
    services: Dict[str, str]
    infradrift_version: str = VERSION

    # ── Serialisation ──────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding='utf-8')

    @classmethod
    def load(cls, path: Path) -> 'StateSnapshot':
        data = json.loads(path.read_text(encoding='utf-8'))
        return cls(
            meta=data.get('meta', {}),
            packages=data.get('packages', {}),
            ports=data.get('ports', []),
            users=data.get('users', []),
            crons=data.get('crons', []),
            services=data.get('services', {}),
            infradrift_version=data.get('infradrift_version', '?'),
        )


def take_snapshot(verbose: bool = False) -> StateSnapshot:
    """Collect current server state into a StateSnapshot."""
    _v = print if verbose else lambda *_: None

    _v('  Collecting metadata...')
    meta = collect_meta()

    _v('  Collecting packages...')
    packages = collect_packages()

    _v('  Collecting open ports...')
    ports = collect_ports()

    _v('  Collecting system users...')
    users = collect_users()

    _v('  Collecting cron jobs...')
    crons = collect_crons()

    _v('  Collecting services...')
    services = collect_services()

    return StateSnapshot(
        meta=meta,
        packages=packages,
        ports=ports,
        users=users,
        crons=crons,
        services=services,
    )
