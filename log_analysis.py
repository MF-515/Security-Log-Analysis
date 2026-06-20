from collections import Counter
import re
import csv

with open("auth.log", "r") as file:
    logs = file.readlines()

failed_attempts = []
ip_addresses = []
usernames = []

for line in logs:

    if "Failed password" in line:

        failed_attempts.append(line)

        ip_match = re.search(
            r'from (\d+\.\d+\.\d+\.\d+)',
            line
        )

        if ip_match:
            ip_addresses.append(ip_match.group(1))

        user_match = re.search(
            r'for (\w+) from',
            line
        )

        if user_match:
            usernames.append(user_match.group(1))

ip_counter = Counter(ip_addresses)
user_counter = Counter(usernames)

print("=" * 60)
print("Security Log Analysis Report")
print("=" * 60)

print(f"\nFailed Login Attempts: {len(failed_attempts)}")

print("\nTop Attacking IPs:")

for ip, count in ip_counter.items():
    print(f"{ip} --> {count}")

print("\nTargeted Usernames:")

for user, count in user_counter.items():
    print(f"{user} --> {count}")

with open("report.csv", "w", newline="") as csvfile:

    writer = csv.writer(csvfile)

    writer.writerow(["IP Address", "Attempts"])

    for ip, count in ip_counter.items():
        writer.writerow([ip, count])

print("\nCSV report generated successfully.")
