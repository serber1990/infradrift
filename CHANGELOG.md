# Changelog

## 1.1.0

### Fixed
- `infradrift check --format json` printed progress messages on stdout, so the output was not valid JSON.
  Progress, warnings and errors now go to stderr.
- `--output` was silently ignored for JSON reports.
- The default baseline path did not match the documentation; it is now `/var/lib/infradrift/baseline.json`
  for root and `~/.config/infradrift/baseline.json` for other users.
- The `ss` parser stored the socket type as its state, and ignored the bind address: a service moving from
  `127.0.0.1` to `0.0.0.0` went unnoticed. The address is now part of the port identity.
- Client UDP sockets in the ephemeral range produced false CRITICAL alerts; they are now INFO.
- `@reboot`/`@daily` cron entries were ignored, as were `/etc/cron.{hourly,daily,weekly,monthly}` scripts
  and other users' crontabs (read from the spool when running as root).
- The tool no longer calls `sudo -n` behind the user's back (it could log authentication failures).
- dpkg packages removed but not purged (`rc`) were reported as installed.
- Service enablement (enabled/disabled) was documented but not collected.
- netstat fallback lost process names containing spaces.
- Terminal colors are disabled when the output is piped or `NO_COLOR` is set.

### Added
- Privileged group membership tracking (sudo, wheel, docker, lxd…): adding a user is CRITICAL.
- pacman (Arch Linux) support.
- Package downgrades are WARNING, upgrades INFO (version-aware comparison, including Debian epochs).
- `--fail-on info|warning|critical|never` and exit code 2 for errors.
- Warning when baseline and check were taken by different users (root vs non-root visibility).
- Baselines are written with `0600` permissions.
- `python -m infradrift`, test suite and GitHub Actions CI.

### Changed
- Snapshots from 1.0 can still be used as baselines.
- License metadata unified (MIT). Requires Python 3.9+.

## 1.0.0

- Initial release.
