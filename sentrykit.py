#!/usr/bin/env python3
"""SentryKit - a lightweight defensive security toolkit (standard library only).

Subcommands:
  scan      TCP port check (ONLY scan hosts you own or have permission to test)
  logs      Detect brute-force login attempts in SSH auth logs
  fim       File integrity monitor (init a baseline, then check for changes)
  password  Password strength check, optional breach lookup (HaveIBeenPwned)
  url       Heuristic phishing check for a URL
  headers   Check an email's headers (.eml file) for spoofing signs

Examples:
  python sentrykit.py scan 127.0.0.1 --ports 1-1024
  python sentrykit.py logs /var/log/auth.log --threshold 5
  python sentrykit.py fim init /etc --baseline base.json
  python sentrykit.py fim check /etc --baseline base.json
  python sentrykit.py password --breach
  python sentrykit.py url "http://paypa1-login.example.xyz/verify"
  python sentrykit.py headers suspicious.eml
"""
import argparse
import getpass
import hashlib
import json
import math
import os
import re
import socket
import string
import sys
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 6379: "redis", 8080: "http-alt",
    27017: "mongodb",
}
RISKY_PORTS = {21, 23, 445, 3389, 6379, 27017}


# ---------------------------------------------------------------- port scan
def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def check_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def cmd_scan(args):
    if not args.yes:
        ans = input(f"Do you own or have written permission to scan {args.host}? [y/N] ")
        if ans.strip().lower() != "y":
            print("Aborted.")
            return 1
    ports = parse_ports(args.ports)
    print(f"Scanning {args.host} ({len(ports)} ports)...")
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = ex.map(lambda p: check_port(args.host, p, args.timeout), ports)
    open_ports = [p for p in results if p]
    if not open_ports:
        print("No open ports found.")
    for p in open_ports:
        flag = "  <-- commonly risky if exposed" if p in RISKY_PORTS else ""
        print(f"  {p}/tcp open  {COMMON_SERVICES.get(p, 'unknown')}{flag}")
    return 0


# ------------------------------------------------------------- log analysis
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")


def cmd_logs(args):
    by_ip, users_by_ip = Counter(), {}
    with open(args.logfile, errors="replace") as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                user, ip = m.groups()
                by_ip[ip] += 1
                users_by_ip.setdefault(ip, set()).add(user)
    flagged = [(ip, n) for ip, n in by_ip.most_common() if n >= args.threshold]
    if not flagged:
        print(f"No IP reached {args.threshold} failed logins.")
        return 0
    print(f"IPs with >= {args.threshold} failed logins:")
    for ip, n in flagged:
        users = sorted(users_by_ip[ip])
        shown = ", ".join(users[:5]) + ("..." if len(users) > 5 else "")
        print(f"  {ip:<16} {n:>5} attempts  users tried: {shown}")
    print("\nConsider blocking these with a firewall or fail2ban.")
    return 0


# ------------------------------------------------------ file integrity (FIM)
def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root):
    snap = {}
    for dirpath, _, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                if os.path.islink(p):
                    continue
                snap[p] = hash_file(p)
            except OSError:
                continue
    return snap


def cmd_fim(args):
    if args.action == "init":
        snap = snapshot(args.path)
        with open(args.baseline, "w") as f:
            json.dump(snap, f, indent=2)
        print(f"Baseline saved: {len(snap)} files -> {args.baseline}")
        return 0
    with open(args.baseline) as f:
        old = json.load(f)
    new = snapshot(args.path)
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(p for p in set(old) & set(new) if old[p] != new[p])
    for label, items in (("ADDED", added), ("REMOVED", removed), ("MODIFIED", changed)):
        for p in items:
            print(f"{label:<9} {p}")
    if not (added or removed or changed):
        print("No changes detected.")
        return 0
    print(f"\n{len(added)} added, {len(removed)} removed, {len(changed)} modified")
    return 2


# -------------------------------------------------------- password checking
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "111111", "iloveyou", "admin", "welcome", "monkey", "dragon", "passw0rd",
    "password1", "123456789", "football", "qwerty123",
}


def password_report(pw):
    issues = []
    pool = 0
    pool += 26 if any(c in string.ascii_lowercase for c in pw) else 0
    pool += 26 if any(c in string.ascii_uppercase for c in pw) else 0
    pool += 10 if any(c in string.digits for c in pw) else 0
    pool += 32 if any(c in string.punctuation for c in pw) else 0
    entropy = len(pw) * math.log2(pool) if pool else 0
    if len(pw) < 12:
        issues.append("shorter than 12 characters")
    if pw.lower() in COMMON_PASSWORDS:
        issues.append("is one of the most common passwords")
        entropy = min(entropy, 10)
    if re.search(r"(.)\1{2,}", pw):
        issues.append("has repeated characters (aaa)")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", pw.lower()):
        issues.append("contains a simple sequence")
    if pw.isalpha() or pw.isdigit():
        issues.append("uses only one character type")
    rating = ("very weak" if entropy < 28 else "weak" if entropy < 36 else
              "fair" if entropy < 60 else "strong" if entropy < 80 else "very strong")
    return rating, entropy, issues


def breach_count(pw):
    """k-anonymity: only the first 5 chars of the SHA-1 leave your machine."""
    sha = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = sha[:5], sha[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "sentrykit"})
    with urllib.request.urlopen(req, timeout=10) as r:
        for line in r.read().decode().splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
    return 0


def cmd_password(args):
    pw = getpass.getpass("Password to check (hidden): ")
    rating, entropy, issues = password_report(pw)
    print(f"Rating: {rating} (~{entropy:.0f} bits of entropy)")
    for i in issues:
        print(f"  - {i}")
    if args.breach:
        try:
            n = breach_count(pw)
            print(f"Breach check: seen {n:,} times in known breaches - don't use it!"
                  if n else "Breach check: not found in known breaches.")
        except Exception as e:
            print(f"Breach check failed: {e}")
    return 0


# ------------------------------------------------------------ URL analysis
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "click", "country", "gq", "tk", "ml", "work"}
KEYWORDS = {"login", "verify", "update", "secure", "account", "banking",
            "password", "confirm", "wallet", "signin", "support"}


def url_report(url):
    if "://" not in url:
        url = "http://" + url
    u = urlparse(url)
    host = (u.hostname or "").lower()
    findings = []
    if u.scheme != "https":
        findings.append((1, "not using HTTPS"))
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        findings.append((3, "host is a raw IP address"))
    if "@" in u.netloc:
        findings.append((3, "contains '@' (can hide the real destination)"))
    if "xn--" in host:
        findings.append((3, "punycode domain (possible look-alike characters)"))
    if host in SHORTENERS:
        findings.append((2, "link shortener hides the destination"))
    if host.count(".") >= 4:
        findings.append((2, "unusually many subdomains"))
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append((2, "TLD frequently abused for phishing"))
    if len(url) > 100:
        findings.append((1, "very long URL"))
    if re.search(r"[a-z][0-9][a-z]|[0o]{2,}|1[il]|l1", host.split(".")[0]) and "-" in host:
        findings.append((1, "digits mixed into brand-like name (typosquatting?)"))
    hits = [k for k in KEYWORDS if k in (host + u.path).lower()]
    if hits:
        findings.append((1 + len(hits) // 2, f"sensitive keywords: {', '.join(hits)}"))
    if host.count("-") >= 3:
        findings.append((1, "many hyphens in domain"))
    score = sum(s for s, _ in findings)
    verdict = "LOW" if score < 3 else "MEDIUM" if score < 6 else "HIGH"
    return verdict, score, [m for _, m in findings]


def cmd_url(args):
    verdict, score, findings = url_report(args.url)
    print(f"Risk: {verdict} (score {score})")
    for f in findings:
        print(f"  - {f}")
    if not findings:
        print("  No heuristic red flags (this does not prove the URL is safe).")
    return 0


# ---------------------------------------------------------- email headers
def addr_domain(value):
    m = re.search(r"@([\w.-]+)", value or "")
    return m.group(1).lower() if m else None


def cmd_headers(args):
    with open(args.eml, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f, headersonly=True)
    frm = addr_domain(msg["From"])
    rp = addr_domain(msg["Return-Path"])
    reply = addr_domain(msg["Reply-To"])
    print(f"From: {msg['From']}\nReturn-Path: {msg['Return-Path']}\nReply-To: {msg['Reply-To']}\n")
    issues = []
    if frm and rp and frm != rp:
        issues.append(f"From domain ({frm}) differs from Return-Path ({rp})")
    if frm and reply and frm != reply:
        issues.append(f"Reply-To domain ({reply}) differs from From ({frm})")
    auth = " ".join(msg.get_all("Authentication-Results") or []).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        status = m.group(1) if m else "missing"
        print(f"{mech.upper():<6}: {status}")
        if status != "pass":
            issues.append(f"{mech.upper()} did not pass ({status})")
    print()
    if issues:
        print("Warning signs:")
        for i in issues:
            print(f"  - {i}")
    else:
        print("No obvious header red flags.")
    return 0


# --------------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description="Defensive security toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="TCP port scan (authorized targets only)")
    s.add_argument("host")
    s.add_argument("--ports", default="1-1024")
    s.add_argument("--timeout", type=float, default=0.5)
    s.add_argument("--workers", type=int, default=100)
    s.add_argument("--yes", action="store_true", help="skip authorization prompt")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("logs", help="detect brute-force SSH logins")
    s.add_argument("logfile")
    s.add_argument("--threshold", type=int, default=5)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("fim", help="file integrity monitor")
    s.add_argument("action", choices=["init", "check"])
    s.add_argument("path")
    s.add_argument("--baseline", default="baseline.json")
    s.set_defaults(func=cmd_fim)

    s = sub.add_parser("password", help="password strength / breach check")
    s.add_argument("--breach", action="store_true", help="check HaveIBeenPwned")
    s.set_defaults(func=cmd_password)

    s = sub.add_parser("url", help="phishing heuristics for a URL")
    s.add_argument("url")
    s.set_defaults(func=cmd_url)

    s = sub.add_parser("headers", help="check email headers in a .eml file")
    s.add_argument("eml")
    s.set_defaults(func=cmd_headers)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
