# Brute Force Login Detector
# Reads a log file and flags IPs with a lot of failed logins

import re
import sys

# how many failed logins before we call it suspicious
THRESHOLD = 5

# this pattern matches the failed login lines in a Linux auth log
# example: Failed password for root from 192.168.1.50 port 22 ssh2
pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")


def read_log(filename):
    # goes through the log and counts failed attempts for each IP
    failed_counts = {}
    users_tried = {}

    try:
        with open(filename, "r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    user = match.group(1)
                    ip = match.group(2)

                    # add 1 to the count for this IP
                    failed_counts[ip] = failed_counts.get(ip, 0) + 1

                    # keep track of which usernames they tried
                    if ip not in users_tried:
                        users_tried[ip] = set()
                    users_tried[ip].add(user)
    except FileNotFoundError:
        print("Couldn't find the file:", filename)
        sys.exit(1)

    return failed_counts, users_tried


def show_alerts(failed_counts, users_tried):
    found_any = False

    for ip, count in failed_counts.items():
        if count >= THRESHOLD:
            found_any = True
            print("[ALERT] Possible brute force from", ip)
            print("        Failed attempts:", count)
            print("        Usernames tried:", ", ".join(users_tried[ip]))
            print()

    if not found_any:
        print("No suspicious IPs found.")


def save_report(failed_counts):
    # saves the flagged IPs to a file so I can look at them later
    with open("alerts.txt", "w") as f:
        for ip, count in failed_counts.items():
            if count >= THRESHOLD:
                f.write(ip + " - " + str(count) + " failed attempts\n")
    print("Report saved to alerts.txt")


def main():
    # use the file from the command line, or the sample log if none given
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "sample_auth.log"

    print("Scanning", filename, "...\n")

    failed_counts, users_tried = read_log(filename)
    show_alerts(failed_counts, users_tried)
    save_report(failed_counts)


main()
