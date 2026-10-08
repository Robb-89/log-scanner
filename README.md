# Log Scanner

![Tests](https://github.com/Robb-89/log-scanner/actions/workflows/tests.yml/badge.svg)

A Python command-line tool that scans SSH authentication logs to detect brute-force login attempts, including fast automated attacks and attacks that succeeded.

## Features

- Flags IP addresses with repeated failed login attempts, whether by password or by SSH key (`Failed publickey`)
- Shows which usernames each flagged IP tried
- Detects bursts: an IP hitting the failure threshold within a short time window, a sign of automated attacks
- Detects possible breaches: an IP that fails repeatedly and then logs in successfully
- Flags IPs that targeted the `root` account specifically
- Ranks flagged IPs from most to fewest failures
- Handles irregular log lines, such as "invalid user" attempts
- Handles leap-day timestamps safely
- Understands both classic syslog timestamps (`Oct 06 14:02:11`) and ISO 8601 timestamps (`2026-10-06T14:02:11`) used by rsyslog/journald
- Configurable log file, threshold, and time window from the command line
- Exports reports as plain text, CSV, or JSON
- Reads from stdin (`--file -`) so logs can be piped in, e.g. from `journalctl`
- Reads `.gz` log files transparently, and a comma-separated list of rotated logs (oldest first) as one continuous scan
- Can write the report to a file (`--output`) instead of stdout
- Prints a summary line (lines scanned, unique IPs, failed attempts, runtime) to stderr on every run
- Caps memory during a massive scanning event: stops tracking new distinct IPs past `--max-tracked-ips` (default 200,000; already-tracked IPs are unaffected)

## Usage

Run with defaults (`auth.log`, threshold of 3, 60-second window, text output):

    python3 scanner.py

Choose a log file, threshold, and time window:

    python3 scanner.py --file /path/to/auth.log --threshold 5 --window 120

Export as JSON or CSV:

    python3 scanner.py --format json
    python3 scanner.py --format csv > report.csv

Pipe a log in instead of pointing at a file, and write the report to disk:

    journalctl -u sshd | python3 scanner.py --file - --output report.txt

Read a gzip-compressed log directly, or scan a set of rotated logs (oldest first) as one continuous log:

    python3 scanner.py --file auth.log.2.gz
    python3 scanner.py --file auth.log.2.gz,auth.log.1,auth.log

Lower or disable the distinct-IP tracking cap (default 200,000; use 0 for no limit):

    python3 scanner.py --max-tracked-ips 50000
    python3 scanner.py --max-tracked-ips 0

See all options:

    python3 scanner.py --help

The included `auth.log` is sample data using reserved documentation IP addresses.

## Example output

The `STATS` line is printed to stderr on every run, independent of `--format`:

    STATS: 18 lines scanned, 3 unique IPs, 9 failed attempts, 0.001s

    ALERT: 192.0.2.200 had 5 failed login attempts before a successful login by ubuntu

    BURST: 192.0.2.200 made 3 or more failed attempts within 60 seconds

    ROOT ATTEMPT: 192.0.2.200 tried logging in as root

    ROOT ATTEMPT: 203.0.113.45 tried logging in as root

    192.0.2.200: 5 failed login attempts
      Usernames tried: admin, oracle, root, ubuntu

    203.0.113.45: 3 failed login attempts
      Usernames tried: admin, root

JSON (`--format json`):

    [
      {
        "ip": "192.0.2.200",
        "failed_attempts": 5,
        "usernames_tried": ["admin", "oracle", "root", "ubuntu"],
        "burst": true,
        "breached_as": "ubuntu",
        "targeted_root": true
      },
      {
        "ip": "203.0.113.45",
        "failed_attempts": 3,
        "usernames_tried": ["admin", "root"],
        "burst": false,
        "breached_as": null,
        "targeted_root": true
      }
    ]

CSV (`--format csv`):

    ip,failed_attempts,usernames_tried,burst,breached_as,targeted_root
    192.0.2.200,5,admin;oracle;root;ubuntu,True,ubuntu,True
    203.0.113.45,3,admin;root,False,,True

## Running tests

Tests are written with pytest:

    pytest

Tests run automatically on every push using GitHub Actions.

## Project structure

- `scanner.py`: the scanner, split into functions for parsing, scanning, and reporting
- `test_scanner.py`: automated tests
- `auth.log`: sample log data
- `.github/workflows/tests.yml`: CI configuration
