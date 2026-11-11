# SentryKit

**A lightweight, all-in-one defensive security toolkit for the command line.**
SentryKit scans ports, analyzes logs, monitors file integrity, checks password strength, and flags phishing URLs and spoofed emails, all from a single Python script with zero dependencies.

## Features

| Command    | What it does                                                                 |
|------------|------------------------------------------------------------------------------|
| `scan`     | TCP port scanner that highlights commonly risky exposed services             |
| `logs`     | Detects brute-force SSH login attempts in auth logs                          |
| `fim`      | File integrity monitor: create a baseline, then detect added/removed/modified files |
| `password` | Strength rating plus optional breach lookup via HaveIBeenPwned (k-anonymity) |
| `url`      | Heuristic phishing check for suspicious links                                |
| `headers`  | Checks `.eml` email headers for SPF/DKIM/DMARC failures and spoofing signs   |

## Requirements

- Python 3.8 or newer
- No third-party packages (standard library only)
- Internet access is needed only for `password --breach`

## Installation

### Linux / macOS

```bash
# 1. Clone the repository
git clone https://github.com/rayanrafiq/Sentry-Kit.git
cd SentryKit

# 2. (Optional) create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install requirements (none needed, but kept for future additions)
pip install -r requirements.txt

# 4. Run it
python3 sentrykit.py --help
```

### Windows (PowerShell)

```powershell
git clone https://github.com/<your-username>/sentrykit.git
cd sentrykit

python -m venv venv
venv\Scripts\Activate.ps1

pip install -r requirements.txt

python sentrykit.py --help
```

### Without Git

Download `sentrykit.py` and run it directly with Python. Nothing else is required.

## Usage

```bash
# Port scan (only scan systems you own or have written permission to test)
python3 sentrykit.py scan 127.0.0.1 --ports 1-1024
python3 sentrykit.py scan 192.168.1.10 --ports 22,80,443 --timeout 1

# Detect brute-force logins (default threshold: 5 failed attempts)
python3 sentrykit.py logs /var/log/auth.log --threshold 5

# File integrity monitoring
python3 sentrykit.py fim init ~/Documents --baseline base.json
python3 sentrykit.py fim check ~/Documents --baseline base.json

# Password strength (input is hidden); add --breach for a breach lookup
python3 sentrykit.py password
python3 sentrykit.py password --breach

# Phishing URL heuristics
python3 sentrykit.py url "http://paypa1-login.example.xyz/verify"

# Email header analysis (save the message as .eml first)
python3 sentrykit.py headers suspicious.eml
```

### Exit codes

- `0`: success / no issues found
- `1`: aborted (e.g., scan authorization declined)
- `2`: `fim check` found changes

This makes SentryKit easy to use in cron jobs and scripts.

## Notes and limitations

- The `url` and `headers` checks are **heuristics**. A clean result does not prove something is safe.
- `logs` currently parses OpenSSH "Failed password" lines. Other formats are not yet supported.
- Reading some logs (e.g. `/var/log/auth.log`) may require `sudo`.
- The password breach check sends only the first 5 characters of the password's SHA-1 hash. The password itself never leaves your machine.

## Responsible use

SentryKit is intended for **defensive and educational use**. Only scan networks and systems that you own or have explicit authorization to test. Unauthorized scanning may be illegal in your jurisdiction. The authors accept no liability for misuse.

## Contributing

Pull requests are welcome. Ideas: more log formats, scheduled FIM checks with email alerts, JSON output, a web dashboard.

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit your changes and open a pull request

## License

Released under the [MIT License](LICENSE).
