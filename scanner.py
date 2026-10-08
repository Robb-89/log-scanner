import argparse
import csv
import json
import sys


def parse_args():
    parser = argparse.ArgumentParser(description="Flag IPs with repeated failed SSH logins.")
    parser.add_argument("--file", default="auth.log", help="Path to the auth.log file")
    parser.add_argument("--threshold", type=int, default=3, help="Number of failed attempts to flag an IP")
    parser.add_argument("--format", choices=["text", "csv", "json"], default="text", help="Output format")
    return parser.parse_args()


def parse_line(line):
    words = line.split()
    spot = words.index("from")
    ip_address = words[spot + 1]
    username = words[spot - 1]
    return ip_address, username


def scan_log(path, threshold):
    counts = {}
    users = {}
    breaches = []

    with open(path) as f:
        for line in f:
            if "Failed password" in line:
                ip_address, username = parse_line(line)
                counts[ip_address] = counts.get(ip_address, 0) + 1

                if ip_address not in users:
                    users[ip_address] = []
                users[ip_address].append(username)

            elif "Accepted password" in line:
                ip_address, username = parse_line(line)
                failures = counts.get(ip_address, 0)
                if failures >= threshold:
                    breaches.append((ip_address, username, failures))

    return counts, users, breaches


def build_report(counts, users, breaches, threshold):
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
                "breached_as": breached.get(ip_address),
            })
    return report


def print_breaches(breaches):
    for ip_address, username, failures in breaches:
        print(f"ALERT: {ip_address} had {failures} failed login attempts before a successful login by {username}")
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
    writer.writerow(["ip", "failed_attempts", "usernames_tried", "breached_as"])
    for row in report:
        writer.writerow([
            row["ip"],
            row["failed_attempts"],
            ";".join(row["usernames_tried"]),
            row["breached_as"] or "",
        ])


def main():
    args = parse_args()
    counts, users, breaches = scan_log(args.file, args.threshold)

    if args.format == "json":
        print_json(build_report(counts, users, breaches, args.threshold))
    elif args.format == "csv":
        print_csv(build_report(counts, users, breaches, args.threshold))
    else:
        print_breaches(breaches)
        print_report(counts, users, args.threshold)


if __name__ == "__main__":
    main()