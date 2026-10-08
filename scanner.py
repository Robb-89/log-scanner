import argparse
import contextlib
import csv
import gzip
import json
import sys
import time
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(description="Flag IPs with repeated failed SSH logins.")
    parser.add_argument(
        "--file",
        default="auth.log",
        help="Path to the auth.log file. Use '-' for stdin, a .gz path to read "
        "gzip-compressed logs transparently, or a comma-separated list of rotated "
        "logs (oldest first, e.g. auth.log.2.gz,auth.log.1,auth.log)",
    )
    parser.add_argument("--output", help="Write the report to this file instead of stdout")
    parser.add_argument("--threshold", type=int, default=3, help="Number of failed attempts to flag an IP")
    parser.add_argument("--window", type=int, default=60, help="Seconds within which threshold failures count as a burst")
    parser.add_argument("--format", choices=["text", "csv", "json"], default="text", help="Output format")
    return parser.parse_args()


def parse_line(line):
    words = line.split()
    spot = words.index("from")
    ip_address = words[spot + 1]
    username = words[spot - 1]
    return ip_address, username


def parse_time(line, year=2000):
    words = line.split()
    timestamp_str = " ".join(words[0:3])
    timestamp = datetime.strptime(f"{year} " + timestamp_str, "%Y %b %d %H:%M:%S")
    return timestamp


def open_log_file(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt")
    return open(path)


def iter_log_lines(path):
    if path == "-":
        yield from sys.stdin
        return

    for single_path in str(path).split(","):
        try:
            f = open_log_file(single_path)
        except OSError as e:
            print(f"Error: could not read log file '{single_path}': {e.strerror}", file=sys.stderr)
            sys.exit(1)
        with f:
            yield from f


def scan_log(path, threshold, window, stats=None):
    counts = {}
    users = {}
    times = {}
    breaches = []
    bursts = []
    current_year = 2000
    last_month = None
    total_lines = 0

    for line in iter_log_lines(path):
        total_lines += 1
        if "Failed password" in line or "Failed publickey" in line:
            try:
                ip_address, username = parse_line(line)
                timestamp = parse_time(line, current_year)
            except (ValueError, IndexError):
                continue

            # Log lines carry no year, so infer rollovers from month
            # going backwards (e.g. Dec -> Jan) to keep timestamps
            # monotonic across a year boundary.
            if last_month is not None and timestamp.month < last_month:
                current_year += 1
                timestamp = parse_time(line, current_year)
            last_month = timestamp.month

            counts[ip_address] = counts.get(ip_address, 0) + 1

            if ip_address not in users:
                users[ip_address] = []
            users[ip_address].append(username)

            if ip_address not in times:
                times[ip_address] = []
            times[ip_address].append(timestamp)

            if len(times[ip_address]) >= threshold:
                newest = times[ip_address][-1]
                oldest = times[ip_address][-threshold]
                gap = (newest - oldest).total_seconds()
                if gap <= window and ip_address not in bursts:
                    bursts.append(ip_address)

        elif "Accepted password" in line:
            try:
                ip_address, username = parse_line(line)
            except (ValueError, IndexError):
                continue
            failures = counts.get(ip_address, 0)
            if failures >= threshold:
                breaches.append((ip_address, username, failures))

    if stats is not None:
        stats["total_lines"] = total_lines

    return counts, users, breaches, bursts


def build_report(counts, users, breaches, bursts, threshold):
    breached = {}
    for ip_address, username, failures in breaches:
        breached[ip_address] = username

    report = []
    for ip_address in sorted(counts, key=counts.get, reverse=True):
        if counts[ip_address] >= threshold:
            report.append({
                "ip": ip_address,
                "failed_attempts": counts[ip_address],
                "usernames_tried": sorted(set(users[ip_address])),
                "burst": ip_address in bursts,
                "breached_as": breached.get(ip_address),
                "targeted_root": "root" in users[ip_address],
            })
    return report


def print_breaches(breaches):
    for ip_address, username, failures in breaches:
        print(f"ALERT: {ip_address} had {failures} failed login attempts before a successful login by {username}")
        print()


def print_bursts(bursts, threshold, window):
    for ip_address in bursts:
        print(f"BURST: {ip_address} made {threshold} or more failed attempts within {window} seconds")
        print()


def print_root_attempts(counts, users, threshold):
    for ip_address in sorted(counts, key=counts.get, reverse=True):
        if counts[ip_address] >= threshold and "root" in users[ip_address]:
            print(f"ROOT ATTEMPT: {ip_address} tried logging in as root")
            print()


def print_report(counts, users, threshold):
    for ip_address in sorted(counts, key=counts.get, reverse=True):
        count = counts[ip_address]
        if count >= threshold:
            names = ", ".join(sorted(set(users[ip_address])))
            print(f"{ip_address}: {count} failed login attempts")
            print(f"  Usernames tried: {names}")
            print()


def print_json(report):
    print(json.dumps(report, indent=2))


def print_csv(report):
    writer = csv.writer(sys.stdout)
    writer.writerow(["ip", "failed_attempts", "usernames_tried", "burst", "breached_as", "targeted_root"])
    for row in report:
        writer.writerow([
            row["ip"],
            row["failed_attempts"],
            ";".join(row["usernames_tried"]),
            row["burst"],
            row["breached_as"] or "",
            row["targeted_root"],
        ])


def print_stats(total_lines, counts, elapsed_seconds):
    unique_ips = len(counts)
    total_failed = sum(counts.values())
    print(
        f"STATS: {total_lines} lines scanned, {unique_ips} unique IPs, "
        f"{total_failed} failed attempts, {elapsed_seconds:.3f}s",
        file=sys.stderr,
    )


def write_report(args, counts, users, breaches, bursts):
    if args.format == "json":
        print_json(build_report(counts, users, breaches, bursts, args.threshold))
    elif args.format == "csv":
        print_csv(build_report(counts, users, breaches, bursts, args.threshold))
    else:
        print_breaches(breaches)
        print_bursts(bursts, args.threshold, args.window)
        print_root_attempts(counts, users, args.threshold)
        print_report(counts, users, args.threshold)


def main():
    args = parse_args()

    stats = {}
    start = time.monotonic()
    counts, users, breaches, bursts = scan_log(args.file, args.threshold, args.window, stats=stats)
    elapsed = time.monotonic() - start
    print_stats(stats["total_lines"], counts, elapsed)

    if args.output:
        try:
            out_file = open(args.output, "w")
        except OSError as e:
            print(f"Error: could not write output file '{args.output}': {e.strerror}", file=sys.stderr)
            return 1
        with out_file, contextlib.redirect_stdout(out_file):
            write_report(args, counts, users, breaches, bursts)
    else:
        write_report(args, counts, users, breaches, bursts)

    return 1 if breaches or bursts else 0


if __name__ == "__main__":
    sys.exit(main())