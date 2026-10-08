from datetime import datetime

from scanner import parse_line, parse_time, scan_log, build_report


def test_parse_line_normal():
    line = "Oct 06 14:02:11 server sshd[2231]: Failed password for root from 203.0.113.45 port 52114 ssh2"
    assert parse_line(line) == ("203.0.113.45", "root")


def test_parse_line_invalid_user():
    line = "Oct 06 14:03:40 server sshd[2251]: Failed password for invalid user test from 192.0.2.88 port 40311 ssh2"
    assert parse_line(line) == ("192.0.2.88", "test")


def test_parse_time():
    line = "Oct 06 14:02:11 server sshd[2231]: Failed password for root from 203.0.113.45 port 52114 ssh2"
    assert parse_time(line) == datetime(2000, 10, 6, 14, 2, 11)


def test_parse_time_leap_day():
    line = "Feb 29 08:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2"
    assert parse_time(line) == datetime(2000, 2, 29, 8, 0, 0)


def test_scan_log_counts_failures(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:02:12 server sshd[1]: Failed password for admin from 10.0.0.1 port 2 ssh2\n"
        "Oct 06 14:02:13 server sshd[1]: Connection closed by 10.0.0.1 port 3\n"
        "Oct 06 14:02:14 server sshd[1]: Failed password for root from 10.0.0.2 port 4 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert counts == {"10.0.0.1": 2, "10.0.0.2": 1}
    assert users["10.0.0.1"] == ["root", "admin"]


def test_scan_log_detects_breach(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:02:12 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "Oct 06 14:02:13 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
        "Oct 06 14:02:14 server sshd[1]: Accepted password for root from 10.0.0.1 port 4 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert breaches == [("10.0.0.1", "root", 3)]


def test_scan_log_ignores_normal_login(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:14 server sshd[1]: Accepted password for robb from 10.0.0.5 port 4 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert breaches == []


def test_scan_log_detects_burst(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:00:05 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "Oct 06 14:00:10 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert bursts == ["10.0.0.1"]


def test_scan_log_slow_failures_are_not_a_burst(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:05:00 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "Oct 06 14:10:00 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert bursts == []


def test_build_report():
    counts = {"10.0.0.1": 4, "10.0.0.2": 1}
    users = {"10.0.0.1": ["root", "admin", "root", "root"], "10.0.0.2": ["test"]}
    breaches = [("10.0.0.1", "root", 4)]
    bursts = ["10.0.0.1"]
    report = build_report(counts, users, breaches, bursts, 3)
    assert report == [
        {
            "ip": "10.0.0.1",
            "failed_attempts": 4,
            "usernames_tried": ["admin", "root"],
            "burst": True,
            "breached_as": "root",
        }
    ]