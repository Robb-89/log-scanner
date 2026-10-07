import argparse

parser = argparse.ArgumentParser(
    description="Flag IPs with repeated failed SSH logins."
)
parser.add_argument("--file", default="auth.log", help="Path to the auth.log file")
parser.add_argument(
    "--threshold", type=int, default=3, help="Number of failed attempts to flag an IP"
)

args = parser.parse_args()


counts = {}
users = {}
breaches = []

with open(args.file) as f:
    for line in f:
        if "Failed password" in line:
            words = line.split()
            spot = words.index("from")
            ip_address = words[spot + 1]
            username = words[spot - 1]
            counts[ip_address] = counts.get(ip_address, 0) + 1

            if ip_address not in users:
                users[ip_address] = []
            users[ip_address].append(username)

        elif "Accepted password" in line:
            words = line.split()
            spot = words.index("from")
            ip_address = words[spot + 1]
            username = words[spot - 1]
            failures = counts.get(ip_address, 0)
            if failures >= args.threshold:
                breaches.append((ip_address, username, failures))

for ip_address, username, failures in breaches:
    print(
        f"ALERT: {ip_address} had {failures} failed login attempts before a successful login by {username}"
    )
    print()


for ip_address in sorted(counts, key=counts.get, reverse=True):
    count = counts[ip_address]
    if count >= args.threshold:
        names = ", ".join(sorted(set(users[ip_address])))
        print(f"{ip_address}: {count} failed login attempts")
        print(f"  Usernames tried: {names}")
        print()
