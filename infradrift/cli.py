#!/usr/bin/env python3
"""
infradrift — snapshot a Linux server and detect drift: packages, ports, users,
privileged groups, cron jobs and systemd services.

Exit codes:  0 no drift (at or above --fail-on)   1 drift detected   2 usage or I/O error
"""
import argparse
import os
import sys
from pathlib import Path

from shellcolorize import Color

from . import __version__
from .diff import diff_snapshots
from .renderer import render_json, render_markdown, render_terminal
from .snapshot import StateSnapshot, default_path, take_snapshot

EXIT_OK, EXIT_DRIFT, EXIT_ERROR = 0, 1, 2
FAIL_LEVELS = {'info': 'INFO', 'warning': 'WARNING', 'critical': 'CRITICAL'}


# Progress, warnings and errors go to stderr so stdout only carries the report.
def _ok(msg: str)   -> None: print(f"  {Color.GREEN}✔{Color.RESET}  {msg}", file=sys.stderr)
def _step(msg: str) -> None: print(f"  {Color.CYAN}▶{Color.RESET}  {msg}", file=sys.stderr)
def _err(msg: str)  -> None: print(f"  {Color.RED}✖{Color.RESET}  {msg}", file=sys.stderr)
def _warn(msg: str) -> None: print(f"  {Color.YELLOW}⚠{Color.RESET}  {msg}", file=sys.stderr)


def _root_hint() -> None:
    if os.geteuid() != 0:
        _warn('Not running as root: other users\' crontabs and some process names are not visible.')

# ── snapshot ──────────────────────────────────────────────────────────────────

def cmd_snapshot(args: argparse.Namespace) -> int:
    output = Path(args.output) if args.output else default_path()
    print(f"\n  {Color.CYAN}{Color.BOLD}infradrift  ·  snapshot{Color.RESET}\n", file=sys.stderr)
    _root_hint()
    snap = take_snapshot(progress=lambda what: _step(f'Collecting {what}...'))

    try:
        snap.save(output)
    except OSError as e:
        _err(f'Cannot write {output}: {e.strerror}')
        if os.geteuid() != 0:
            _err('Use --output to choose another location, or run with sudo.')
        return EXIT_ERROR

    print()
    _ok(f'Baseline saved: {output}')
    managers = ', '.join(f'{m} {len(p)}' for m, p in snap.packages.items()) or 'none'
    print(f'  Packages : {sum(len(p) for p in snap.packages.values())}  ({managers})')
    print(f'  Ports    : {len(snap.ports)} listening')
    print(f'  Users    : {len(snap.users)} accounts, {len(snap.groups)} privileged groups')
    print(f'  Crons    : {len(snap.crons)} jobs')
    print(f'  Services : {len(snap.services)} units')
    print()
    return EXIT_OK

# ── check / diff ──────────────────────────────────────────────────────────────

def _load(path: Path):
    try:
        return StateSnapshot.load(path)
    except FileNotFoundError:
        _err(f'Snapshot not found: {path}')
    except PermissionError:
        _err(f'Permission denied: {path} (baselines are only readable by their owner)')
    except (OSError, ValueError, TypeError) as e:
        _err(f'Cannot read snapshot {path}: {e}')
    return None


def _report(report, args: argparse.Namespace) -> int:
    b_user, c_user = report.baseline_meta.get('user'), report.current_meta.get('user')
    if b_user and c_user and b_user != c_user:
        _warn(f'Baseline taken as "{b_user}", current state as "{c_user}": '
              'some differences may only be visibility differences.')

    fmt = args.format
    if fmt == 'terminal' and args.output:
        fmt = 'markdown' if str(args.output).endswith('.md') else 'json'

    if fmt == 'terminal':
        render_terminal(report)
    else:
        text = render_json(report) if fmt == 'json' else render_markdown(report)
        if args.output:
            try:
                Path(args.output).write_text(text + '\n', encoding='utf-8')
            except OSError as e:
                _err(f'Cannot write {args.output}: {e.strerror}')
                return EXIT_ERROR
            _ok(f'Report saved to {args.output}')
        else:
            print(text)

    if args.fail_on == 'never':
        return EXIT_OK
    return EXIT_DRIFT if report.has_at_least(FAIL_LEVELS[args.fail_on]) else EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline) if args.baseline else default_path()
    if not baseline_path.exists():
        _err(f'Baseline not found: {baseline_path}')
        _err("Run 'infradrift snapshot' first to create one.")
        return EXIT_ERROR
    baseline = _load(baseline_path)
    if baseline is None:
        return EXIT_ERROR
    _step('Collecting current state...')
    return _report(diff_snapshots(baseline, take_snapshot()), args)


def cmd_diff(args: argparse.Namespace) -> int:
    snap_a, snap_b = _load(Path(args.snapshot_a)), _load(Path(args.snapshot_b))
    if snap_a is None or snap_b is None:
        return EXIT_ERROR
    return _report(diff_snapshots(snap_a, snap_b), args)

# ── main ──────────────────────────────────────────────────────────────────────

def _add_report_options(p: argparse.ArgumentParser) -> None:
    p.add_argument('--format', '-f', choices=['terminal', 'json', 'markdown'], default='terminal',
                   help='Report format (default: terminal)')
    p.add_argument('--output', '-o', metavar='FILE',
                   help='Write the report to FILE (json or markdown; inferred from .md/.json if needed)')
    p.add_argument('--fail-on', choices=['info', 'warning', 'critical', 'never'], default='info',
                   help='Lowest severity that makes the exit code 1 (default: info = any change)')


def build_parser() -> argparse.ArgumentParser:
    default = default_path()
    parser = argparse.ArgumentParser(
        prog='infradrift',
        description='Detect drift between a known-good baseline and the current state of a Linux server.',
        epilog='exit codes: 0 no drift · 1 drift detected · 2 error',
    )
    parser.add_argument('-v', '--version', action='version', version=f'infradrift {__version__}')
    sub = parser.add_subparsers(dest='command', metavar='COMMAND')

    p_snap = sub.add_parser('snapshot', help='Capture the current state as baseline')
    p_snap.add_argument('--output', '-o', metavar='FILE', help=f'Baseline output path (default: {default})')

    p_check = sub.add_parser('check', help='Compare the current state against the baseline')
    p_check.add_argument('--baseline', '-b', metavar='FILE',
                         help=f'Baseline to compare against (default: {default})')
    _add_report_options(p_check)

    p_diff = sub.add_parser('diff', help='Compare two snapshot files')
    p_diff.add_argument('snapshot_a', metavar='BASELINE')
    p_diff.add_argument('snapshot_b', metavar='CURRENT')
    _add_report_options(p_diff)
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    Color.auto()

    if args.command is None:
        parser.print_help()
        sys.exit(EXIT_OK)

    dispatch = {'snapshot': cmd_snapshot, 'check': cmd_check, 'diff': cmd_diff}
    try:
        sys.exit(dispatch[args.command](args))
    except KeyboardInterrupt:
        _err('Interrupted')
        sys.exit(130)


if __name__ == '__main__':
    main()
