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

## Usage

Run with defaults (`auth.log`, threshold of 3):

    python3 scanner.py

Choose a log file and threshold:

    python3 scanner.py --file /path/to/auth.log --threshold 5

See all options:

    python3 scanner.py --help

The included `auth.log` is sample data using reserved documentation IP addresses.

## Example output

    ALERT: 192.0.2.200 had 5 failed login attempts before a successful login by ubuntu

    192.0.2.200: 5 failed login attempts
      Usernames tried: admin, oracle, root, ubuntu

    203.0.113.45: 3 failed login attempts
      Usernames tried: admin, root

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

- Export reports to CSV or JSON
- Support newer log timestamp formats
- Flag only failures that occur within a short time window