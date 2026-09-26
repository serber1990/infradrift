import copy

import pytest

from infradrift.diff import diff_snapshots
from infradrift.snapshot import StateSnapshot

BASE = dict(
    meta={"hostname": "prod-01", "captured_at": "2026-05-10T09:00:00+02:00", "user": "root",
          "ephemeral_port_start": 32768},
    packages={"apt": {"nginx": "1.24.0-2", "openssl": "3.0.13-0ubuntu3", "curl": "8.5.0-2"}},
    ports=[{"proto": "tcp", "address": "*", "port": 22, "state": "LISTEN", "process": "sshd"},
           {"proto": "tcp", "address": "127.0.0.1", "port": 6379, "state": "LISTEN", "process": "redis-server"}],
    users=[{"name": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
           {"name": "backup", "uid": 34, "gid": 34, "home": "/var/backups", "shell": "/usr/sbin/nologin"}],
    groups={"sudo": ["alice"], "docker": []},
    crons=[{"schedule": "0 3 * * *", "command": "/usr/local/bin/backup.sh", "source": "/etc/crontab"}],
    services={"nginx": {"active": "active", "enabled": "enabled"},
              "cron": {"active": "active", "enabled": "enabled"}},
)


@pytest.fixture
def base():
    return copy.deepcopy(BASE)


def report(a, b):
    return diff_snapshots(StateSnapshot(**a), StateSnapshot(**b))


def found(a, b):
    return {(c.description, c.severity) for c in report(a, b).changes}


def test_identical_is_clean(base):
    assert report(base, base).is_clean


def test_packages(base):
    cur = copy.deepcopy(base)
    cur["packages"]["apt"]["nginx"] = "1.26.0-1"        # upgrade
    cur["packages"]["apt"]["openssl"] = "3.0.2-0ubuntu1"  # downgrade
    del cur["packages"]["apt"]["curl"]
    cur["packages"]["apt"]["netcat"] = "1.226-1"
    f = found(base, cur)
    assert ("[apt] nginx upgraded", "INFO") in f
    assert ("[apt] openssl downgraded", "WARNING") in f
    assert ("[apt] curl removed", "WARNING") in f
    assert ("[apt] netcat installed", "INFO") in f


def test_new_port_and_exposure_change(base):
    cur = copy.deepcopy(base)
    cur["ports"][1]["address"] = "*"                      # redis now on all interfaces
    cur["ports"].append({"proto": "tcp", "address": "*", "port": 4444, "state": "LISTEN", "process": "nc"})
    f = found(base, cur)
    assert ("6379/tcp on all interfaces  (redis-server) — now listening on a new address", "CRITICAL") in f
    assert ("4444/tcp on all interfaces  (nc) — new listening port", "CRITICAL") in f
    assert not any("no longer listening" in d for d, _ in f)


def test_high_udp_ports_are_info(base):
    cur = copy.deepcopy(base)
    cur["ports"].append({"proto": "udp", "address": "*", "port": 50555, "state": "UNCONN", "process": ""})
    cur["ports"].append({"proto": "udp", "address": "*", "port": 161, "state": "UNCONN", "process": "snmpd"})
    sev = {d.split(" ")[0]: s for d, s in found(base, cur)}
    assert sev["50555/udp"] == "INFO" and sev["161/udp"] == "CRITICAL"


def test_users_and_groups(base):
    cur = copy.deepcopy(base)
    cur["users"][1]["shell"] = "/bin/bash"
    cur["users"].append({"name": "deploy", "uid": 1005, "gid": 1005, "home": "/home/deploy", "shell": "/bin/bash"})
    cur["groups"]["docker"] = ["deploy"]
    r = report(base, cur)
    f = {(c.description, c.severity) for c in r.changes}
    assert ("backup — account changed", "CRITICAL") in f
    assert ("deploy — new user", "CRITICAL") in f
    assert ("deploy added to privileged group docker", "CRITICAL") in f
    assert next(c for c in r.changes if c.description.startswith("backup")).detail == \
        "shell /usr/sbin/nologin → /bin/bash"


def test_crons_and_services(base):
    cur = copy.deepcopy(base)
    cur["crons"].append({"schedule": "@reboot", "command": "/tmp/.x/run", "source": "crontab:www-data"})
    cur["services"]["nginx"]["active"] = "failed"
    cur["services"]["cron"]["enabled"] = "disabled"
    cur["services"]["miner"] = {"active": "active", "enabled": "enabled"}
    f = found(base, cur)
    assert ("New cron job: @reboot  /tmp/.x/run", "WARNING") in f
    assert ("nginx  active → failed", "WARNING") in f
    assert ("cron  enabled → disabled", "WARNING") in f
    assert ("miner — new service", "WARNING") in f


def test_critical_first(base):
    cur = copy.deepcopy(base)
    cur["packages"]["apt"]["vim"] = "9.1"
    cur["users"].append({"name": "eve", "uid": 0, "gid": 0, "home": "/", "shell": "/bin/sh"})
    assert report(base, cur).changes[0].severity == "CRITICAL"


def test_snapshots_from_1_0_are_supported(base):
    old = copy.deepcopy(base)
    old.pop("groups")
    old["ports"] = [{"proto": "tcp", "port": 22, "state": "tcp", "process": "sshd"},
                    {"proto": "tcp", "port": 6379, "state": "tcp", "process": "redis-server"}]
    old["services"] = {"nginx": "running", "cron": "running"}
    r = report(old, base)
    assert not any(c.category == "services" and c.kind != "changed" for c in r.changes)
    assert any(c.description.startswith("6379/tcp") for c in r.changes)  # 127.0.0.1 vs old wildcard
