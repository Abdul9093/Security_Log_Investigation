# Security Log Investigation

## Project Description
This Python project analyses firewall and authentication log files to investigate security-related activity.

## Input Files
- `firewall.log`
- `authentication.log`
- `suspicious_ips.txt`

## Main Features
- Counts valid and malformed firewall log lines.
- Analyses allowed and blocked events.
- Identifies top blocked source IP addresses.
- Analyses successful and failed login attempts.
- Identifies frequently targeted usernames.
- Generates TXT, CSV and JSON reports.
- Handles missing files and unexpected data.

## Requirements
- Python 3
- Thonny IDE

## How to Run
1. Download or clone this repository.
2. Open `main.py` in Thonny.
3. Click Run.
4. Check the generated reports.

## Output Files
- `security_report.txt`
- `security_report.csv`
- `security_report.json`
- `username_report.txt`
