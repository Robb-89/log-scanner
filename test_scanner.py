import gzip
import io
import sys
from datetime import datetime

import pytest

from scanner import parse_line, parse_time, scan_log, build_report, main, print_stats


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


def test_parse_time_iso_format():
    line = "2026-10-06T14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2"
    assert parse_time(line) == datetime(2026, 10, 6, 14, 2, 11)


def test_parse_time_iso_format_with_offset_and_microseconds():
    line = "2026-10-06T14:02:11.123456+00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2"
    assert parse_time(line) == datetime(2026, 10, 6, 14, 2, 11, 123456)


def test_parse_time_iso_format_with_z_suffix():
    line = "2026-10-06T14:02:11Z server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2"
    assert parse_time(line) == datetime(2026, 10, 6, 14, 2, 11)


def test_scan_log_mixes_offset_aware_and_naive_iso_lines(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "2026-10-06T14:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "2026-10-06T14:00:05Z server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "2026-10-06T14:00:10+00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert counts == {"10.0.0.1": 3}
    assert bursts == ["10.0.0.1"]


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


def test_scan_log_breach_count_resets_after_login(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:00:01 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "Oct 06 14:00:02 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
        "Oct 06 14:00:03 server sshd[1]: Accepted password for root from 10.0.0.1 port 4 ssh2\n"
        "Oct 06 15:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 5 ssh2\n"
        "Oct 06 15:00:01 server sshd[1]: Accepted password for root from 10.0.0.1 port 6 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    # Only the real breach is reported; a single mistype after a
    # successful login should not retrigger an alert with an inflated,
    # lifetime-cumulative failure count.
    assert breaches == [("10.0.0.1", "root", 3)]
    assert counts == {"10.0.0.1": 4}


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


def test_scan_log_handles_iso_format_log(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "2026-10-06T14:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "2026-10-06T14:00:05 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "2026-10-06T14:00:10 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
        "2026-10-06T14:00:11 server sshd[1]: Accepted password for root from 10.0.0.1 port 4 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert counts == {"10.0.0.1": 3}
    assert bursts == ["10.0.0.1"]
    assert breaches == [("10.0.0.1", "root", 3)]


def test_scan_log_iso_format_year_boundary_not_a_false_burst(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "2025-12-31T23:59:55 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "2026-01-01T00:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "2026-01-01T05:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert bursts == []


def test_scan_log_year_rollover_skips_unparseable_leap_day(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        # A sparse log that jumps straight from Dec to Feb (skipping Jan)
        # bumps the guessed year by one for the rollover check. If that
        # guessed year isn't a leap year, re-parsing "Feb 29" used to
        # raise an uncaught ValueError and crash the whole scan.
        "Dec 31 23:59:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Feb 29 08:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert counts == {"10.0.0.1": 1}


def test_parse_time_explicit_year():
    line = "Jan 01 00:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2"
    assert parse_time(line, year=2001) == datetime(2001, 1, 1, 0, 0, 0)


def test_scan_log_year_rollover_not_a_false_burst(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Dec 31 23:59:55 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Jan 01 00:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "Jan 01 05:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert bursts == []


def test_scan_log_detects_burst_across_year_rollover(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Dec 31 23:59:55 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Jan 01 00:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "Jan 01 00:00:05 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
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


def test_scan_log_counts_failed_publickey(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Failed publickey for root from 10.0.0.1 port 1 ssh2: RSA SHA256:abcd\n"
        "Oct 06 14:02:12 server sshd[1]: Failed publickey for root from 10.0.0.1 port 2 ssh2: RSA SHA256:abcd\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert counts == {"10.0.0.1": 2}
    assert users["10.0.0.1"] == ["root", "root"]


def test_scan_log_mixes_password_and_publickey_failures(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:02:12 server sshd[1]: Failed publickey for root from 10.0.0.1 port 2 ssh2: RSA SHA256:abcd\n"
        "Oct 06 14:02:13 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert counts == {"10.0.0.1": 3}


def test_build_report_flags_targeted_root():
    counts = {"10.0.0.1": 3, "10.0.0.2": 3}
    users = {"10.0.0.1": ["root", "admin", "root"], "10.0.0.2": ["admin", "guest", "admin"]}
    report = build_report(counts, users, [], [], 3)
    targeted_root = {row["ip"]: row["targeted_root"] for row in report}
    assert targeted_root == {"10.0.0.1": True, "10.0.0.2": False}


def test_print_root_attempts_only_above_threshold(capsys):
    from scanner import print_root_attempts

    counts = {"10.0.0.1": 3, "10.0.0.2": 2}
    users = {"10.0.0.1": ["root"], "10.0.0.2": ["root"]}
    print_root_attempts(counts, users, threshold=3)
    out = capsys.readouterr().out
    assert "10.0.0.1" in out
    assert "10.0.0.2" not in out


def test_scan_log_skips_malformed_line(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Failed password for root\n"
        "Oct 06 14:02:12 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "Oct 06 14:02:13 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(log, 3, 60)
    assert counts == {"10.0.0.1": 2}


def test_scan_log_reads_gzip_file(tmp_path):
    log = tmp_path / "auth.log.1.gz"
    with gzip.open(log, "wt") as f:
        f.write("Oct 06 14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n")
        f.write("Oct 06 14:02:12 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n")
    counts, users, breaches, bursts = scan_log(log, 2, 60)
    assert counts == {"10.0.0.1": 2}


def test_scan_log_reads_comma_separated_rotated_logs(tmp_path):
    older = tmp_path / "auth.log.1.gz"
    with gzip.open(older, "wt") as f:
        f.write("Oct 06 14:00:00 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n")
        f.write("Oct 06 14:00:05 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n")
    newer = tmp_path / "auth.log"
    newer.write_text(
        "Oct 06 14:00:10 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    counts, users, breaches, bursts = scan_log(f"{older},{newer}", 3, 60)
    assert counts == {"10.0.0.1": 3}
    assert bursts == ["10.0.0.1"]


def test_scan_log_tracks_total_lines_in_stats(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:02:12 server sshd[1]: Connection closed by 10.0.0.1 port 3\n"
    )
    stats = {}
    scan_log(log, 3, 60, stats=stats)
    assert stats["total_lines"] == 2


def test_print_stats_output(capsys):
    print_stats(total_lines=10, counts={"10.0.0.1": 3, "10.0.0.2": 1}, elapsed_seconds=0.5)
    err = capsys.readouterr().err
    assert "10 lines scanned" in err
    assert "2 unique IPs" in err
    assert "4 failed attempts" in err


def test_scan_log_reads_from_stdin(monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            "Oct 06 14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
            "Oct 06 14:02:12 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        ),
    )
    counts, users, breaches, bursts = scan_log("-", 3, 60)
    assert counts == {"10.0.0.1": 2}


def test_main_writes_report_to_output_file(tmp_path, monkeypatch):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Accepted password for robb from 10.0.0.5 port 4 ssh2\n"
    )
    output = tmp_path / "report.txt"
    monkeypatch.setattr(
        sys, "argv", ["scanner.py", "--file", str(log), "--output", str(output)]
    )
    assert main() == 0
    assert output.exists()


def test_main_output_file_error_returns_nonzero(tmp_path, monkeypatch, capsys):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Accepted password for robb from 10.0.0.5 port 4 ssh2\n"
    )
    bad_output = tmp_path / "no-such-dir" / "report.txt"
    monkeypatch.setattr(
        sys, "argv", ["scanner.py", "--file", str(log), "--output", str(bad_output)]
    )
    assert main() == 1
    assert "could not write output file" in capsys.readouterr().err


def test_scan_log_missing_file_exits_cleanly(tmp_path, capsys):
    missing = tmp_path / "missing.log"
    with pytest.raises(SystemExit) as exc_info:
        scan_log(missing, 3, 60)
    assert exc_info.value.code == 1
    assert "could not read log file" in capsys.readouterr().err


def test_main_returns_nonzero_when_findings(tmp_path, monkeypatch):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Failed password for root from 10.0.0.1 port 1 ssh2\n"
        "Oct 06 14:02:12 server sshd[1]: Failed password for root from 10.0.0.1 port 2 ssh2\n"
        "Oct 06 14:02:13 server sshd[1]: Failed password for root from 10.0.0.1 port 3 ssh2\n"
    )
    monkeypatch.setattr(sys, "argv", ["scanner.py", "--file", str(log), "--threshold", "3"])
    assert main() == 1


def test_main_returns_zero_when_clean(tmp_path, monkeypatch):
    log = tmp_path / "test.log"
    log.write_text(
        "Oct 06 14:02:11 server sshd[1]: Accepted password for root from 10.0.0.1 port 1 ssh2\n"
    )
    monkeypatch.setattr(sys, "argv", ["scanner.py", "--file", str(log), "--threshold", "3"])
    assert main() == 0


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
            "targeted_root": True,
        }
    ]