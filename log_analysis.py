from collections import Counter
import re

with open("auth.log", "r") as file:
    logs = file.readlines()

failed_logins = []
ip_addresses = []

for line in logs:
    if "Failed password" in line:
        failed_logins.append(line)

        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

        if ip_match:
            ip_addresses.append(ip_match.group(1))

print("=" * 50)
print("Security Log Analysis Report")
print("=" * 50)

print(f"\nTotal Failed Login Attempts: {len(failed_logins)}")

print("\nTop Source IP Addresses:")

ip_count = Counter(ip_addresses)

for ip, count in ip_count.items():
    print(f"{ip} --> {count} attempts")
