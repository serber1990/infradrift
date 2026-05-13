#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from shellcolorize import Color

from .snapshot import StateSnapshot, take_snapshot, DEFAULT_PATH
from .diff import diff_snapshots
from .renderer import render_terminal, render_markdown, render_json

VERSION = "1.0.0"


def _ok(msg: str)   -> None: print(f"  {Color.GREEN}✔{Color.RESET}  {msg}")
def _step(msg: str) -> None: print(f"  {Color.CYAN}▶{Color.RESET}  {msg}")
def _err(msg: str)  -> None: print(f"  {Color.RED}✖{Color.RESET}  {msg}")
def _warn(msg: str) -> None: print(f"  {Color.YELLOW}⚠{Color.RESET}  {msg}")


# ── snapshot ──────────────────────────────────────────────────────────────────

def cmd_snapshot(args: argparse.Namespace) -> int:
    output = Path(args.output) if args.output else DEFAULT_PATH

    print()
    print(f"  {Color.CYAN}{Color.BOLD}infradrift  ·  snapshot{Color.RESET}")
    print()
    _step(f'Capturing server state...')

    snap = take_snapshot(verbose=True)

    _step(f'Saving baseline to {output}...')
    try:
        snap.save(output)
    except PermissionError:
        _err(f'Permission denied: {output}')
        return 1

    print()
    _ok(f'Baseline saved: {output}')
    _ok(f'Packages : {sum(len(v) for v in snap.packages.values())} entries '
        f'({", ".join(snap.packages.keys())})')
    _ok(f'Ports    : {len(snap.ports)} listening')
    _ok(f'Users    : {len(snap.users)} accounts')
    _ok(f'Crons    : {len(snap.crons)} jobs')
    _ok(f'Services : {len(snap.services)} units')
    print()
    return 0


# ── check ─────────────────────────────────────────────────────────────────────

def cmd_check(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline) if args.baseline else DEFAULT_PATH

    if not baseline_path.exists():
        _err(f'Baseline not found: {baseline_path}')
        _err("Run 'infradrift snapshot' first to create one.")
        return 1

    _step('Loading baseline...')
    try:
        baseline = StateSnapshot.load(baseline_path)
    except Exception as e:
        _err(f'Failed to load baseline: {e}')
        return 1

    _step('Collecting current state...')
    current = take_snapshot(verbose=False)

    _step('Comparing...')
    report = diff_snapshots(baseline, current)

    fmt = getattr(args, 'format', 'terminal')

    if fmt == 'json':
        print(render_json(report))
    elif fmt == 'markdown':
        output = getattr(args, 'output', None)
        md = render_markdown(report)
        if output:
            Path(output).write_text(md, encoding='utf-8')
            _ok(f'Report saved to {output}')
        else:
            print(md)
    else:
        render_terminal(report)

    return 1 if report.changes else 0  # non-zero exit = drift detected


# ── diff ──────────────────────────────────────────────────────────────────────

def cmd_diff(args: argparse.Namespace) -> int:
    try:
        snap_a = StateSnapshot.load(Path(args.snapshot_a))
        snap_b = StateSnapshot.load(Path(args.snapshot_b))
    except FileNotFoundError as e:
        _err(f'File not found: {e}')
        return 1
    except Exception as e:
        _err(f'Failed to load snapshot: {e}')
        return 1

    report = diff_snapshots(snap_a, snap_b)

    fmt = getattr(args, 'format', 'terminal')
    if fmt == 'json':
        print(render_json(report))
    elif fmt == 'markdown':
        output = getattr(args, 'output', None)
        md = render_markdown(report)
        if output:
            Path(output).write_text(md, encoding='utf-8')
            _ok(f'Report saved to {output}')
        else:
            print(md)
    else:
        render_terminal(report)

    return 1 if report.changes else 0


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog='infradrift',
        description='Detect drift between declared and actual server state.',
    )
    parser.add_argument('-v', '--version', action='version', version=f'infradrift {VERSION}')
    sub = parser.add_subparsers(dest='command', metavar='COMMAND')

    # snapshot
    p_snap = sub.add_parser('snapshot', help='Capture current state as baseline')
    p_snap.add_argument('--output', '-o', metavar='FILE',
                        help=f'Baseline output path (default: {DEFAULT_PATH})')

    # check
    p_check = sub.add_parser('check', help='Compare current state against baseline')
    p_check.add_argument('--baseline', '-b', metavar='FILE',
                         help=f'Baseline to compare against (default: {DEFAULT_PATH})')
    p_check.add_argument('--format', '-f', choices=['terminal', 'json', 'markdown'],
                         default='terminal', help='Output format (default: terminal)')
    p_check.add_argument('--output', '-o', metavar='FILE',
                         help='Save report to file (markdown format only)')

    # diff
    p_diff = sub.add_parser('diff', help='Compare any two snapshot files')
    p_diff.add_argument('snapshot_a', metavar='BASELINE')
    p_diff.add_argument('snapshot_b', metavar='CURRENT')
    p_diff.add_argument('--format', '-f', choices=['terminal', 'json', 'markdown'],
                        default='terminal', help='Output format (default: terminal)')
    p_diff.add_argument('--output', '-o', metavar='FILE',
                        help='Save report to file (markdown format only)')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {'snapshot': cmd_snapshot, 'check': cmd_check, 'diff': cmd_diff}
    sys.exit(dispatch[args.command](args))


if __name__ == '__main__':
    main()
