counts = {}

with open("auth.log") as f:
    for line in f:
        if "Failed password" in line:
            words = line.split()
            spot = words.index("from")
            ip_address = words[spot + 1]
            counts[ip_address] = counts.get(ip_address, 0) + 1

for ip_address in sorted(counts, key=counts.get, reverse=True):
    count = counts[ip_address]
    if count >= 3:
        print(f"{ip_address}: {count} failed login attempts")