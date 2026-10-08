import argparse
import csv
import json
import sys
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(description="Flag IPs with repeated failed SSH logins.")
    parser.add_argument("--file", default="auth.log", help="Path to the auth.log file")
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


def parse_time(line):
    words = line.split()
    timestamp_str = " ".join(words[0:3])
    timestamp = datetime.strptime("2000 " + timestamp_str, "%Y %b %d %H:%M:%S")
    return timestamp


def scan_log(path, threshold, window):
    counts = {}
    users = {}
    times = {}
    breaches = []
    bursts = []

    try:
        f = open(path)
    except OSError as e:
        print(f"Error: could not read log file '{path}': {e.strerror}", file=sys.stderr)
        sys.exit(1)

    with f:
        for line in f:
            if "Failed password" in line:
                try:
                    ip_address, username = parse_line(line)
                    timestamp = parse_time(line)
                except (ValueError, IndexError):
                    continue
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
    writer.writerow(["ip", "failed_attempts", "usernames_tried", "burst", "breached_as"])
    for row in report:
        writer.writerow([
            row["ip"],
            row["failed_attempts"],
            ";".join(row["usernames_tried"]),
            row["burst"],
            row["breached_as"] or "",
        ])


def main():
    args = parse_args()
    counts, users, breaches, bursts = scan_log(args.file, args.threshold, args.window)

    if args.format == "json":
        print_json(build_report(counts, users, breaches, bursts, args.threshold))
    elif args.format == "csv":
        print_csv(build_report(counts, users, breaches, bursts, args.threshold))
    else:
        print_breaches(breaches)
        print_bursts(bursts, args.threshold, args.window)
        print_report(counts, users, args.threshold)


if __name__ == "__main__":
    main()