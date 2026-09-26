"""
Dependency-free version comparison, good enough for drift reports.

Handles PEP 440-ish ("2.0.0rc1"), semver ("1.2.3-beta.1") and Debian-style
epochs ("1:2.3-4"). Returns None when a version cannot be interpreted.
"""
import re
from typing import Optional, Tuple

_EPOCH = re.compile(r'^(\d+):')
_RELEASE = re.compile(r'^[vV]?(\d+(?:\.\d+)*)')
_PRE = re.compile(r'(?:a|alpha|b|beta|c|rc|pre|preview|dev)\.?\d*$|-(?:alpha|beta|rc|pre|dev)', re.I)


def _parse(v: str) -> Optional[Tuple[int, Tuple[int, ...], bool]]:
    v = v.strip()
    epoch = 0
    m = _EPOCH.match(v)
    if m:
        epoch, v = int(m.group(1)), v[m.end():]
    m = _RELEASE.match(v)
    if not m:
        return None
    release = tuple(int(x) for x in m.group(1).split('.'))
    rest = v[m.end():]
    return epoch, release, bool(_PRE.search(rest))


def compare_versions(a: str, b: str) -> Optional[int]:
    """-1 if a < b, 0 if equal, 1 if a > b, None if either is not a version."""
    pa, pb = _parse(a), _parse(b)
    if pa is None or pb is None:
        return None
    (ea, ra, pre_a), (eb, rb, pre_b) = pa, pb
    width = max(len(ra), len(rb))
    ra, rb = ra + (0,) * (width - len(ra)), rb + (0,) * (width - len(rb))
    # A pre-release sorts before its final release: 2.0.0rc1 < 2.0.0.
    key_a, key_b = (ea, ra, not pre_a), (eb, rb, not pre_b)
    if key_a == key_b:
        return 0
    return 1 if key_a > key_b else -1


def same_minor(a: str, b: str) -> bool:
    """True when both versions share major.minor (3.12.1 vs 3.12.4)."""
    pa, pb = _parse(a), _parse(b)
    if pa is None or pb is None:
        return False
    return pa[0] == pb[0] and pa[1][:2] == pb[1][:2]
