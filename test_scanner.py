from scanner import parse_line, scan_log, build_report

def test_parse_line_normal():
    line = "Oct 06 14:02:11 server sshd[2231]: Failed password for root from 203.0.113.45 port 52114 ssh2"
    assert parse_line(line) == ("203.0.113.45", "root")


def test_parse_line_invalid_user():
    line = "Oct 06 14:03:40 server sshd[2251]: Failed password for invalid user test from 192.0.2.88 port 40311 ssh2"
    assert parse_line(line) == ("192.0.2.88", "test")


def test_scan_log_counts_failures(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:02:12 server sshd[1]: Failed password for admin from 10.0.0.1 port 2 ssh2\n"
        "Oct 06 14:02:13 server sshd[1]: Connection closed by 10.0.0.1 port 3\n"
        "Oct 06 14:02:14 server sshd[1]: Failed password for root from 10.0.0.2 port 4 ssh2\n"
    )
    counts, users, breaches = scan_log(log, 3)
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
    counts, users, breaches = scan_log(log, 3)
    assert breaches == [("10.0.0.1", "root", 3)]


def test_scan_log_ignores_normal_login(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:14 server sshd[1]: Accepted password for robb from 10.0.0.5 port 4 ssh2\n"
    )
    counts, users, breaches = scan_log(log, 3)
    assert breaches == []


def test_build_report():
    counts = {"10.0.0.1": 4, "10.0.0.2": 1}
    users = {"10.0.0.1": ["root", "admin", "root", "root"], "10.0.0.2": ["test"]}
    breaches = [("10.0.0.1", "root", 4)]
    report = build_report(counts, users, breaches, 3)
    assert report == [
        {
            "ip": "10.0.0.1",
            "failed_attempts": 4,
            "usernames_tried": ["admin", "root"],
            "breached_as": "root",
        }
    ]