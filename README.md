# Log Scanner

![Tests](https://github.com/Robb-89/log-scanner/actions/workflows/tests.yml/badge.svg)

A Python command-line tool that scans SSH authentication logs to detect brute-force login attempts, including attacks that succeeded.

## Features

- Flags IP addresses with repeated failed login attempts
- Shows which usernames each flagged IP tried
- Detects possible breaches: an IP that fails repeatedly and then logs in successfully
- Ranks flagged IPs from most to fewest failures
- Handles irregular log lines, such as "invalid user" attempts
- Configurable log file and alert threshold from the command line
- Exports reports as plain text, CSV, or JSON

## Usage

Run with defaults (`auth.log`, threshold of 3, text output):

    python3 scanner.py

Choose a log file and threshold:

    python3 scanner.py --file /path/to/auth.log --threshold 5

Export as JSON or CSV:

    python3 scanner.py --format json
    python3 scanner.py --format csv > report.csv

See all options:

    python3 scanner.py --help

The included `auth.log` is sample data using reserved documentation IP addresses.

## Example output

    ALERT: 192.0.2.200 had 5 failed login attempts before a successful login by ubuntu

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
        "breached_as": "ubuntu"
      },
      {
        "ip": "203.0.113.45",
        "failed_attempts": 3,
        "usernames_tried": ["admin", "root"],
        "breached_as": null
      }
    ]

CSV (`--format csv`):

    ip,failed_attempts,usernames_tried,breached_as
    192.0.2.200,5,admin;oracle;root;ubuntu,ubuntu
    203.0.113.45,3,admin;root,

## Running tests

Tests are written with pytest:

    pytest

Tests run automatically on every push using GitHub Actions.

## Project structure

- `scanner.py`: the scanner, split into functions for parsing, scanning, and reporting
- `test_scanner.py`: automated tests
- `auth.log`: sample log data
- `.github/workflows/tests.yml`: CI configuration

## Planned improvements

- Support newer log timestamp formats
- Flag only failures that occur within a short time window