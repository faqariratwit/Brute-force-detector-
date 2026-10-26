# Brute Force Login Detector

A small Python project I made that looks through a login log and flags IP addresses with a lot of failed login attempts.

## Why I made this
I'm studying cybersecurity and wanted to try building something that shows how someone could catch a brute force attack. That's when an attacker keeps guessing passwords over and over until one works. This was a way for me to practice Python and learn how log files actually look.

## What it does
- Reads a log file like `auth.log`
- Counts how many times each IP failed to log in
- Flags any IP with 5 or more failed attempts
- Shows which usernames they tried
- Saves the flagged IPs to `alerts.txt`

## How to run it
You need Python 3. Put all the files in one folder, open a terminal there, and run:

```
python brute_force_detector.py
```

If you want to use your own log file, add its name at the end:

```
python brute_force_detector.py yourlogfile.log
```

## Example output
```
[ALERT] Possible brute force from 203.0.113.45
        Failed attempts: 6
        Usernames tried: oracle, test, root, admin
```

## Files
- `brute_force_detector.py` is the main script
- `sample_auth.log` is fake log data I made to test it
- `alerts.txt` is the report it creates

## What I want to add later
- Only count attempts that happen close together in time
- Email alerts
- Support for other kinds of logs,
- 
- If this text looks like Ai, then you're correct I wasn't really trying to write everything down blame my laziness 
