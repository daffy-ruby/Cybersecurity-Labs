import re
import html
import math
import secrets
import random
import sqlite3
import hashlib
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

HOST = "127.0.0.1"
PORT = 8000


# ============================================================
# SECURITY VALIDATION FUNCTIONS
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

# Filename allows:
# letters, numbers, underscore, hyphen, period
FILENAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def validate_email(value):
    value = value.strip()

    if not value:
        return False, "Email address is required."

    if len(value) > 254:
        return False, "Email address is too long."

    if EMAIL_RE.fullmatch(value):
        return True, "Valid email address."

    return False, "Invalid email address."


def validate_filename(value):
    value = value.strip()

    if not value:
        return False, "Filename is required."

    if len(value) > 255:
        return False, "Filename is too long."

    # Reject path separators and traversal
    if "/" in value or "\\" in value:
        return False, "Path separators are not allowed in filenames."

    if ".." in value:
        return False, "Directory traversal sequence detected."

    if not FILENAME_RE.fullmatch(value):
        return False, "Filename contains unsupported characters."

    return True, "Filename accepted."


def validate_file_path(value):
    value = value.strip()

    if not value:
        return False, "File path is required."

    # Convert slash styles consistently
    normalized = value.replace("\\", "/")

    # Reject absolute paths
    if normalized.startswith("/"):
        return False, "Absolute paths are not permitted."

    # Windows drive path
    if re.match(r"^[A-Za-z]:", normalized):
        return False, "Absolute Windows paths are not permitted."

    # Normalize path safely
    parts = []

    for part in normalized.split("/"):
        if part in ("", "."):
            continue

        if part == "..":
            if parts:
                parts.pop()
            else:
                return False, "Directory traversal detected."

        else:
            parts.append(part)

    safe_path = "/".join(parts)

    # Verify normalized path remains relative
    if not safe_path:
        return False, "Empty path is not permitted."

    return True, f"Safe normalized path: {safe_path}"


# ============================================================
# SQL INJECTION DEMONSTRATION
# ============================================================

SQLI_PATTERNS = [
    r"'\s*or\s*'?\d*'?\s*=\s*'?\d",
    r"'\s*or\s+1\s*=\s*1",
    r"union\s+select",
    r";\s*drop\s+table",
    r"--",
    r"/\*",
    r"\*/",
]


def detect_sql_injection(value):
    value_lower = value.lower()

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, value_lower):
            return True

    return False


def sql_injection_test(value):
    value = value.strip()

    if not value:
        return {
            "status": "FAILED",
            "message": "Please enter a value to test."
        }

    suspicious = detect_sql_injection(value)

    # Demonstration of safe parameterized SQL.
    # User input is NEVER concatenated into SQL.
    connection = sqlite3.connect(":memory:")

    try:
        connection.execute(
            "CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT)"
        )

        connection.execute(
            "INSERT INTO patients (name) VALUES (?)",
            ("Demo Patient",)
        )

        connection.execute(
            "SELECT id, name FROM patients WHERE name = ?",
            (value,)
        )

        if suspicious:
            return {
                "status": "PASSED",
                "message": "Potential SQL injection pattern detected and treated as untrusted input.",
                "protection": "Parameterized SQL is enabled.",
                "result": "SQL injection blocked."
            }

        return {
            "status": "PASSED",
            "message": "Input was handled safely.",
            "protection": "Parameterized SQL is enabled.",
            "result": "No SQL injection pattern detected."
        }

    finally:
        connection.close()


# ============================================================
# XSS PREVENTION
# ============================================================

XSS_PATTERNS = [
    r"<\s*script\b",
    r"</\s*script\s*>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<\s*iframe\b",
    r"<\s*object\b",
    r"<\s*embed\b",
]


def detect_xss(value):
    value_lower = value.lower()

    for pattern in XSS_PATTERNS:
        if re.search(pattern, value_lower):
            return True

    return False


def xss_test(value):
    value = value.strip()

    if not value:
        return {
            "status": "FAILED",
            "message": "Please enter content to test."
        }

    detected = detect_xss(value)

    safe_output = html.escape(value, quote=True)

    if detected:
        return {
            "status": "PASSED",
            "message": "Potential HTML/script content detected.",
            "protection": "Output encoding applied.",
            "result": "XSS execution prevented.",
            "encoded": safe_output
        }

    return {
        "status": "PASSED",
        "message": "No dangerous script pattern detected.",
        "protection": "Output encoding available.",
        "result": "Input can be safely rendered as text.",
        "encoded": safe_output
    }


# ============================================================
# SECURE RANDOMNESS
# ============================================================

def generate_secure_number():
    return secrets.randbelow(900000000) + 100000000


def generate_session_token():
    return secrets.token_urlsafe(32)


def generate_password_reset_token():
    return secrets.token_urlsafe(32)


# ============================================================
# ENTROPY ANALYSIS
# ============================================================

def shannon_entropy(values):
    if not values:
        return 0.0

    counts = {}

    for value in values:
        counts[value] = counts.get(value, 0) + 1

    total = len(values)
    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_randomness():
    # Generate 1,000 secure random bytes
    values = list(secrets.token_bytes(1000))

    entropy = shannon_entropy(values)

    unique_values = len(set(values))

    frequency = {}

    for value in values:
        frequency[value] = frequency.get(value, 0) + 1

    maximum_frequency = max(frequency.values())

    return {
        "samples": 1000,
        "unique_values": unique_values,
        "entropy_bits": round(entropy, 4),
        "maximum_frequency": maximum_frequency,
        "source": "Python secrets module",
        "csprng": "YES",
        "result": "Cryptographic randomness analysis completed."
    }


# ============================================================
# WEAK SEED VS CSPRNG
# ============================================================

def compare_randomness():

    # Weak/reproducible PRNG demonstration
    weak1 = random.Random(12345)
    weak2 = random.Random(12345)

    weak_sequence_1 = [weak1.randint(0, 999999) for _ in range(5)]
    weak_sequence_2 = [weak2.randint(0, 999999) for _ in range(5)]

    reproducible = weak_sequence_1 == weak_sequence_2

    # Cryptographically secure sequence
    secure_sequence = [
        secrets.randbelow(1000000)
        for _ in range(5)
    ]

    return {
        "fixed_seed_sequence_1": weak_sequence_1,
        "fixed_seed_sequence_2": weak_sequence_2,
        "reproducible": reproducible,
        "csprng_sequence": secure_sequence,
        "conclusion": (
            "Fixed seed produces a reproducible sequence. "
            "CSPRNG is intended for security-sensitive values."
        )
    }


# ============================================================
# FORMATTING / BUFFER OVERFLOW AWARENESS
# ============================================================

def formatting_test(value):

    try:
        requested_length = int(value)

    except (ValueError, TypeError):
        return {
            "valid": False,
            "result": "Please enter a valid whole number."
        }

    if requested_length < 1:
        return {
            "valid": False,
            "requested_length": requested_length,
            "generated_length": 0,
            "result": "Input length must be at least 1 character."
        }

    if requested_length > 20000:
        return {
            "valid": False,
            "requested_length": requested_length,
            "generated_length": 0,
            "result": "Maximum demonstration length is 20,000 characters."
        }

    # Generate the requested number of characters.
    generated_input = "A" * requested_length

    generated_length = len(generated_input)

    # Demonstration safety limit.
    MAX_SAFE_LENGTH = 10000

    if generated_length > MAX_SAFE_LENGTH:

        return {
            "valid": False,
            "requested_length": requested_length,
            "generated_length": generated_length,
            "result": (
                "Input exceeds the configured 10,000-character "
                "demonstration limit. The application should "
                "reject or limit oversized input."
            ),
            "safe_concept": 'printf("%s", user_input)',
            "unsafe_concept": "printf(user_input)"
        }

    return {
        "valid": True,
        "requested_length": requested_length,
        "generated_length": generated_length,
        "result": (
            "Input length is within the configured "
            "10,000-character demonstration limit."
        ),
        "safe_concept": 'printf("%s", user_input)',
        "unsafe_concept": "printf(user_input)"
    }

# ============================================================
# HTML
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<title>Healthcare Portal - Security Testing Console</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #f3f7fb;
    color: #17243b;
    font-family: Arial, Helvetica, sans-serif;
}

header {
    background: #14758c;
    color: white;
    padding: 18px 7%;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo h1 {
    margin: 0;
    font-size: 28px;
}

.logo p {
    margin: 4px 0 0;
    font-size: 15px;
}

nav a {
    color: white;
    text-decoration: none;
    margin-left: 25px;
}

.container {
    width: 90%;
    max-width: 1400px;
    margin: 35px auto;
}

.hero {
    background: white;
    padding: 30px;
    border-radius: 18px;
    box-shadow: 0 5px 25px rgba(0,0,0,.07);
    margin-bottom: 25px;
}

.hero h2 {
    margin-top: 0;
    font-size: 34px;
}

.hero p {
    color: #60738d;
    font-size: 17px;
}

.console {
    background: white;
    padding: 25px;
    border-radius: 18px;
    box-shadow: 0 5px 25px rgba(0,0,0,.07);
}

.console h2 {
    margin-top: 0;
}

.description {
    color: #60738d;
}

.grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 22px;
    margin-top: 25px;
}

.card {
    border: 1px solid #d9e3ed;
    border-radius: 15px;
    padding: 25px;
    background: #fff;
}

.card h3 {
    margin-top: 0;
    font-size: 22px;
}

input,
textarea {
    width: 100%;
    padding: 15px;
    border: 1px solid #c8d6e5;
    border-radius: 10px;
    font-size: 16px;
    margin-top: 12px;
}

textarea {
    min-height: 130px;
    resize: vertical;
}

button {
    margin-top: 12px;
    padding: 13px 22px;
    background: #2867e8;
    color: white;
    border: none;
    border-radius: 9px;
    font-size: 16px;
    font-weight: bold;
    cursor: pointer;
}

button:hover {
    background: #1854ca;
}

.result {
    display: none;
    margin-top: 18px;
    padding: 16px;
    border-radius: 10px;
    background: #eef6ff;
    border-left: 5px solid #2867e8;
    line-height: 1.7;
    word-break: break-word;
}

.result.show {
    display: block;
}

.success {
    color: #087443;
    font-weight: bold;
}

.failure {
    color: #b42318;
    font-weight: bold;
}

.result pre {
    white-space: pre-wrap;
    word-break: break-word;
}

.code-box {
    background: #f6f8fb;
    border: 1px solid #d9e3ed;
    border-radius: 10px;
    padding: 14px;
    margin-top: 10px;
    overflow-x: auto;
    font-family: Consolas, Monaco, monospace;
    font-size: 14px;
    line-height: 1.5;
}

.rule-list {
    margin: 10px 0 0 20px;
    color: #53657d;
    line-height: 1.7;
}

.info-box {
    margin-top: 20px;
    padding: 18px;
    border-radius: 12px;
    background: #f6f9fc;
    border: 1px solid #d9e3ed;
}

footer {
    text-align: center;
    color: #708198;
    padding: 30px;
}

@media(max-width: 900px) {
    .grid {
        grid-template-columns: 1fr;
    }

    header {
        flex-direction: column;
        gap: 15px;
    }
}

</style>
</head>

<body>

<header>

<div class="logo">
    <h1>Healthcare Portal</h1>
    <p>Patient Registration & Services</p>
</div>

<nav>
    <a href="/">Home</a>
    <a href="#appointments">Appointments</a>
    <a href="#records">Medical Records</a>
    <a href="#login">Login</a>
    <a href="#register">Register</a>
    <a href="#security">Security Testing</a>
</nav>

</header>


<div class="container">

<section class="hero">

    <h2>Healthcare made simple.</h2>

    <p>
        Securely manage appointments, medical records,
        prescriptions and patient information from one place.
    </p>

</section>


<section class="console" id="security">

<h2>Lab 4 Security Testing Console</h2>

<p class="description">
Course demonstration of secure input validation,
secure randomness and common application security controls.
</p>


<div class="grid">


<!-- EMAIL -->

<div class="card">

<h3>Email Validation</h3>

<input
    id="email"
    type="text"
    autocomplete="off"
>

<button onclick="testEmail()">
Test Email
</button>

<div id="emailResult" class="result"></div>

</div>


<!-- FILENAME -->

<div class="card">

<h3>Filename Validation</h3>

<input
    id="filename"
    type="text"
    autocomplete="off"
>

<button onclick="testFilename()">
Test Filename
</button>

<div id="filenameResult" class="result"></div>

</div>


<!-- FILE PATH -->

<div class="card">

<h3>File Path Validation</h3>

<input
    id="filepath"
    type="text"
    autocomplete="off"
>

<button onclick="testPath()">
Check Path
</button>

<div id="pathResult" class="result"></div>

</div>



<!-- SQL -->

<div class="card">

<h3>SQL Injection</h3>

<input
    id="sql"
    type="text"
    autocomplete="off"
>

<button onclick="testSQL()">
Run Demo
</button>

<div id="sqlResult" class="result"></div>

</div>



<!-- XSS -->

<div class="card">

<h3>XSS Prevention</h3>

<textarea
    id="xss"
></textarea>

<button onclick="testXSS()">
Encode Safely
</button>

<div id="xssResult" class="result"></div>

</div>


<!-- RANDOM NUMBER -->

<div class="card">

<h3>Secure Random Number</h3>

<button onclick="generateNumber()">
Generate Number
</button>

<div id="randomResult" class="result"></div>

</div>


<!-- SESSION TOKEN -->

<div class="card">

<h3>Session Token Test</h3>

<button onclick="generateSession()">
Generate Test Token
</button>

<div id="sessionResult" class="result"></div>

</div>


<!-- PASSWORD RESET -->

<div class="card">

<h3>Password Reset Token Test</h3>

<button onclick="generateReset()">
Generate Test Token
</button>

<div id="resetResult" class="result"></div>

</div>


<!-- ENTROPY -->

<div class="card">

<h3>Randomness & Entropy Analysis</h3>

<button onclick="analyzeEntropy()">
Analyze Randomness
</button>

<div id="entropyResult" class="result"></div>

</div>


<!-- CSPRNG -->

<div class="card">

<h3>Weak Seed vs CSPRNG</h3>

<button onclick="compareRandom()">
Compare
</button>

<div id="compareResult" class="result"></div>

</div>


<!-- BUFFER -->

<div class="card">

<h3>Formatting / Buffer Overflow Awareness</h3>

<p>
Enter the number of characters to generate for the input-size test.
</p>

<input
    id="formatLength"
    type="number"
    min="1"
    max="20000"
    placeholder="Enter input length"
>

<button onclick="testFormatting()">
Generate & Test Input
</button>

<div id="formatResult" class="result"></div>

</div>


</div>

</section>

</div>


<footer>
Healthcare Portal — Security Testing Demonstration
</footer>


<script>

async function post(action, value = "") {

    const response = await fetch("/", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body:
            "action=" + encodeURIComponent(action) +
            "&value=" + encodeURIComponent(value)
    });

    return await response.json();
}


function show(id, html) {

    const element = document.getElementById(id);

    element.innerHTML = html;

    element.classList.add("show");
}


async function testEmail() {

    const value = document.getElementById("email").value;

    const data = await post("email", value);

    const cls =
        data.valid ? "success" : "failure";

    show(
        "emailResult",
        `<span class="${cls}">
        ${data.valid ? "✓ VALID" : "✗ INVALID"}
        </span>
        <br>${data.message}`
    );
}


async function testFilename() {

    const value =
        document.getElementById("filename").value;

    const data =
        await post("filename", value);

    const cls =
        data.valid ? "success" : "failure";

    show(
        "filenameResult",
        `<span class="${cls}">
        ${data.valid ? "✓ ACCEPTED" : "✗ REJECTED"}
        </span>
        <br>${data.message}`
    );
}


async function testPath() {

    const value =
        document.getElementById("filepath").value;

    const data =
        await post("path", value);

    const cls =
        data.valid ? "success" : "failure";

    show(
        "pathResult",
        `<span class="${cls}">
        ${data.valid ? "✓ SAFE PATH" : "✗ UNSAFE PATH"}
        </span>
        <br>${data.message}`
    );
}


async function testSQL() {

    const value =
        document.getElementById("sql").value;

    const data =
        await post("sql", value);

    show(
        "sqlResult",
        `<span class="success">
        ✓ SECURITY TEST COMPLETED
        </span>
        <br>${data.message}
        <br><b>Protection:</b> ${data.protection || ""}
        <br><b>Result:</b> ${data.result || ""}`
    );
}


async function testXSS() {

    const value =
        document.getElementById("xss").value;

    if (!value.trim()) {
        show(
            "xssResult",
            `<span class="failure">
            ✗ PLEASE ENTER CONTENT
            </span>
            <br>Please enter content to test.`
        );
        return;
    }

    const data =
        await post("xss", value);

    show(
        "xssResult",
        `<span class="success">
        ✓ XSS PROTECTION TEST COMPLETED
        </span>
        <br>${data.message}
        <br><b>Protection:</b> ${data.protection || ""}
        <br><b>Result:</b> ${data.result || ""}
        <br><b>Encoded output:</b>
        <pre>${escapeHtml(data.encoded || "")}</pre>`
    );
}


async function generateNumber() {

    const data =
        await post("random");

    show(
        "randomResult",
        `<span class="success">
        ✓ SECURE RANDOM NUMBER GENERATED
        </span>
        <br><b>Value:</b> ${data.value}
        <br><b>Source:</b> Python secrets module
        <br><b>CSPRNG:</b> YES`
    );
}


async function generateSession() {

    const data =
        await post("session");

    show(
        "sessionResult",
        `<span class="success">
        ✓ SESSION TOKEN GENERATED
        </span>
        <br><b>Token:</b>
        <pre>${escapeHtml(data.token)}</pre>
        <br><b>Source:</b> Python secrets module`
    );
}


async function generateReset() {

    const data =
        await post("reset");

    show(
        "resetResult",
        `<span class="success">
        ✓ PASSWORD RESET TOKEN GENERATED
        </span>
        <br><b>Token:</b>
        <pre>${escapeHtml(data.token)}</pre>
        <br><b>Source:</b> Python secrets module`
    );
}


async function analyzeEntropy() {

    const data =
        await post("entropy");

    show(
        "entropyResult",
        `<span class="success">
        ✓ ANALYSIS COMPLETED
        </span>
        <br><b>Samples:</b> ${data.samples}
        <br><b>Unique byte values:</b> ${data.unique_values}
        <br><b>Observed Shannon entropy:</b>
        ${data.entropy_bits} bits
        <br><b>Maximum observed frequency:</b>
        ${data.maximum_frequency}
        <br><b>Source:</b> ${data.source}
        <br><b>CSPRNG:</b> ${data.csprng}`
    );
}


async function compareRandom() {

    const data =
        await post("compare");

    show(
        "compareResult",
        `<span class="success">
        ✓ COMPARISON COMPLETED
        </span>
        <br><b>Fixed seed sequence 1:</b>
        <pre>${data.fixed_seed_sequence_1.join(", ")}</pre>

        <b>Fixed seed sequence 2:</b>
        <pre>${data.fixed_seed_sequence_2.join(", ")}</pre>

        <b>Reproducible:</b>
        ${data.reproducible ? "YES" : "NO"}

        <br><b>CSPRNG sequence:</b>
        <pre>${data.csprng_sequence.join(", ")}</pre>

        <br>${data.conclusion}`
    );
}


async function testFormatting() {

    const length =
        document.getElementById("formatLength").value;

    if (!length) {
        show(
            "formatResult",
            `<span class="failure">
            ✗ PLEASE ENTER A LENGTH
            </span>`
        );
        return;
    }

    const data =
        await post("format", length);

    const cls =
        data.valid ? "success" : "failure";

    show(
        "formatResult",
        `<span class="${cls}">
        ${data.valid ? "✓ INPUT SIZE TEST COMPLETED" : "✗ INPUT SIZE TEST FAILED"}
        </span>

        <br><b>Requested length:</b>
        ${data.requested_length} characters

        <br><b>Generated length:</b>
        ${data.generated_length} characters

        <br><b>Result:</b>
        ${data.result}

        <br><b>Safe concept:</b>
        <code>${escapeHtml(data.safe_concept || "")}</code>

        <br><b>Unsafe concept:</b>
        <code>${escapeHtml(data.unsafe_concept || "")}</code>`
    );
}


function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

</script>

</body>
</html>
"""


# ============================================================
# HTTP SERVER
# ============================================================

class Handler(BaseHTTPRequestHandler):

    def send_json(self, data):

        import json

        body = json.dumps(data).encode("utf-8")

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.end_headers()

        self.wfile.write(body)


    def do_GET(self):

        if self.path in ("/", "/validation"):

            body = HTML.encode("utf-8")

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/html; charset=utf-8"
            )

            self.send_header(
                "Content-Length",
                str(len(body))
            )

            self.end_headers()

            self.wfile.write(body)

        else:

            self.send_error(404, "Not Found")


    def do_POST(self):

        length = int(
            self.headers.get("Content-Length", 0)
        )

        body = self.rfile.read(length).decode("utf-8")

        form = parse_qs(body)

        action = form.get("action", [""])[0]

        value = form.get("value", [""])[0]


        # EMAIL
        if action == "email":

            valid, message = validate_email(value)

            self.send_json({
                "valid": valid,
                "message": message
            })

            return


        # FILENAME
        if action == "filename":

            valid, message = validate_filename(value)

            self.send_json({
                "valid": valid,
                "message": message
            })

            return


        # PATH
        if action == "path":

            valid, message = validate_file_path(value)

            self.send_json({
                "valid": valid,
                "message": message
            })

            return


        # SQL
        if action == "sql":

            self.send_json(
                sql_injection_test(value)
            )

            return


        # XSS
        if action == "xss":

            self.send_json(
                xss_test(value)
            )

            return


        # RANDOM NUMBER
        if action == "random":

            self.send_json({
                "value": generate_secure_number()
            })

            return


        # SESSION TOKEN
        if action == "session":

            self.send_json({
                "token": generate_session_token()
            })

            return


        # RESET TOKEN
        if action == "reset":

            self.send_json({
                "token": generate_password_reset_token()
            })

            return


        # ENTROPY
        if action == "entropy":

            self.send_json(
                analyze_randomness()
            )

            return


        # WEAK VS CSPRNG
        if action == "compare":

            self.send_json(
                compare_randomness()
            )

            return


        # FORMATTING
        if action == "format":

            self.send_json(
                formatting_test(value)
            )

            return


        self.send_json({
            "error": "Unknown action."
        })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    server = HTTPServer(
        (HOST, PORT),
        Handler
    )

    print()
    print("==============================================")
    print("        HEALTHCARE PORTAL")
    print("        SECURITY TESTING LAB")
    print("==============================================")
    print()
    print(f"Server running at:")
    print(f"http://{HOST}:{PORT}")
    print()
    print("Open the address in your browser.")
    print("All security tests use this single URL.")
    print()
    print("Press Ctrl+C to stop the server.")
    print()

    try:
        server.serve_forever()

    except KeyboardInterrupt:

        print("\nServer stopped.")

        server.server_close()