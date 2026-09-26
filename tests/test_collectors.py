from infradrift.collectors import parse_cron, parse_netstat, parse_passwd, parse_ss, parse_systemd

SS = """Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      4096          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      4096             [::]:22            [::]:*     users:(("sshd",pid=812,fd=4))
tcp   LISTEN 0      511         127.0.0.1:6379       0.0.0.0:*     users:(("redis-server",pid=90,fd=6))
udp   UNCONN 0      0       127.0.0.53%lo:53         0.0.0.0:*
udp   UNCONN 0      0             0.0.0.0:51820      0.0.0.0:*
"""


def test_parse_ss():
    ports = parse_ss(SS)
    assert ports[0] == {"proto": "tcp", "address": "*", "port": 22, "state": "LISTEN", "process": "sshd"}
    assert ports[1]["address"] == "*"                 # [::] is a wildcard too
    assert ports[2]["address"] == "127.0.0.1" and ports[2]["process"] == "redis-server"
    assert ports[3] == {"proto": "udp", "address": "127.0.0.53%lo", "port": 53, "state": "UNCONN", "process": ""}
    assert len(ports) == 5


def test_parse_netstat():
    out = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd
tcp6       0      0 :::80                   :::*                    LISTEN      99/nginx: master
udp        0      0 0.0.0.0:68              0.0.0.0:*                           501/dhclient
"""
    ports = parse_netstat(out)
    assert [(p["proto"], p["address"], p["port"], p["process"]) for p in ports] == [
        ("tcp", "*", 22, "sshd"), ("tcp", "*", 80, "nginx"), ("udp", "*", 68, "dhclient")]


def test_parse_passwd():
    users = parse_passwd("root:x:0:0:root:/root:/bin/bash\n# comment\nbroken\ndeploy:x:1005:1005::/home/deploy:/bin/sh\n")
    assert [u["name"] for u in users] == ["root", "deploy"]
    assert users[1] == {"name": "deploy", "uid": 1005, "gid": 1005, "home": "/home/deploy", "shell": "/bin/sh"}


def test_parse_cron_includes_special_schedules():
    text = """SHELL=/bin/bash
MAILTO=root
# m h dom mon dow command
*/5 * * * * /usr/local/bin/backup.sh --quiet
@reboot /opt/agent/start.sh
17 * * * * root cd / && run-parts --report /etc/cron.hourly
"""
    jobs = parse_cron(text, "/etc/crontab")
    assert [(j["schedule"], j["command"]) for j in jobs] == [
        ("*/5 * * * *", "/usr/local/bin/backup.sh --quiet"),
        ("@reboot", "/opt/agent/start.sh"),
        ("17 * * * *", "root cd / && run-parts --report /etc/cron.hourly"),
    ]


def test_parse_systemd_merges_state_and_enablement():
    units = """nginx.service      loaded active   running A high performance web server
cron.service       loaded inactive dead    Regular background program processing daemon
"""
    files = """nginx.service      enabled  enabled
cron.service       disabled enabled
getty@.service     enabled  enabled
backup.service     disabled enabled
"""
    services = parse_systemd(units, files)
    assert services == {
        "nginx": {"active": "active", "enabled": "enabled"},
        "cron": {"active": "inactive", "enabled": "disabled"},
        "backup": {"active": "inactive", "enabled": "disabled"},
    }
