# Log Scanner

A Python script that scans SSH authentication logs and flags IP addresses with repeated failed login attempts, a common sign of brute-force attacks.

## What it does
- Reads an SSH auth log line by line
- Filters out noise and keeps only failed password attempts
- Extracts the source IP, including from lines with irregular formats (for example, "invalid user" attempts)
- Counts failures per IP
- Reports IPs at or above a threshold, sorted from most to fewest failures

## How to run
python3 scanner.py

The included auth.log is sample data using reserved documentation IP addresses.

## Example output
192.0.2.200: 5 failed login attempts
203.0.113.45: 3 failed login attempts

## Planned improvements
- Show usernames attempted by each IP
- Command-line options for file and threshold
- Detect failed attempts followed by a successful login