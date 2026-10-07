counts = {}
users = {}

with open("auth.log") as f:
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

for ip_address in sorted(counts, key=counts.get, reverse=True):
    count = counts[ip_address]
    if count >= 3:
        names = ", ".join(sorted(set(users[ip_address])))
        print(f"{ip_address}: {count} failed login attempts")
        print(f"  Usernames tried: {names}")
        print()