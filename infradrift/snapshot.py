"""
StateSnapshot — captures and persists full server state.
"""
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List

from . import __version__
from .collectors import (
    collect_crons, collect_groups, collect_meta, collect_packages,
    collect_ports, collect_services, collect_users,
)


def default_path() -> Path:
    """System-wide baseline for root, per-user baseline otherwise."""
    if os.geteuid() == 0:
        return Path('/var/lib/infradrift/baseline.json')
    config = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    return Path(config) / 'infradrift' / 'baseline.json'


@dataclass
class StateSnapshot:
    meta:     Dict
    packages: Dict[str, Dict[str, str]]
    ports:    List[Dict]
    users:    List[Dict]
    crons:    List[Dict]
    services: Dict[str, Dict[str, str]]
    groups:   Dict[str, List[str]] = field(default_factory=dict)
    infradrift_version: str = __version__

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + '\n', encoding='utf-8')
        path.chmod(0o600)   # the baseline describes users, ports and cron commands

    @classmethod
    def load(cls, path: Path) -> 'StateSnapshot':
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise ValueError('not an infradrift snapshot (expected a JSON object)')
        return cls(
            meta=data.get('meta', {}),
            packages=data.get('packages', {}),
            ports=data.get('ports', []),
            users=data.get('users', []),
            crons=data.get('crons', []),
            services=data.get('services', {}),
            groups=data.get('groups', {}),
            infradrift_version=data.get('infradrift_version', '?'),
        )


def take_snapshot(progress: Callable[[str], None] = lambda _msg: None) -> StateSnapshot:
    """Collect the current server state. `progress` receives a message before each step."""
    progress('metadata')
    meta = collect_meta()
    progress('packages')
    packages = collect_packages()
    progress('listening ports')
    ports = collect_ports()
    progress('users and privileged groups')
    users, groups = collect_users(), collect_groups()
    progress('cron jobs')
    crons = collect_crons()
    progress('services')
    services = collect_services()
    return StateSnapshot(meta=meta, packages=packages, ports=ports, users=users,
                         crons=crons, services=services, groups=groups)
