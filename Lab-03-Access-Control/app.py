from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
    flash
)

import sqlite3
import hashlib
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = "caresecure-lab3-secret-key-change-this"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(BASE_DIR, "caresecure.db")
SECURE_FILES_DIR = os.path.join(BASE_DIR, "secure_files")

os.makedirs(SECURE_FILES_DIR, exist_ok=True)

PATIENT_FILE = os.path.join(
    SECURE_FILES_DIR,
    "patient_record.txt"
)


# ============================================================
# USER ACCESS RULES
# ============================================================
# These rules are used internally by the server.
#
# Doctor -> Read + Write
# Nurse  -> Read
# Guest  -> Read
#
# These permissions are NOT displayed on the website.

ROLE_ACTIONS = {
    "Doctor": {"read", "write"},
    "Nurse": {"read"},
    "Guest": {"read"}
}


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Guest'
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# INITIAL PATIENT RECORD
# ============================================================

DEFAULT_PATIENT_RECORD = """Patient ID: P1001
Patient Name: John Anderson
Email: john.anderson@example.com
Phone: 416-555-0198
Diagnosis: Community-acquired pneumonia
Doctor: Dr. Sarah Williams
Next Appointment: 2026-10-05 10:30
"""


def initialize_patient_file():

    if not os.path.exists(PATIENT_FILE):

        with open(
            PATIENT_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(DEFAULT_PATIENT_RECORD)


# ============================================================
# SHA-256 INTEGRITY
# ============================================================

def calculate_file_hash():

    sha256 = hashlib.sha256()

    with open(
        PATIENT_FILE,
        "rb"
    ) as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


def save_integrity_hash():

    hash_file = PATIENT_FILE + ".sha256"

    current_hash = calculate_file_hash()

    with open(
        hash_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(current_hash)


def verify_integrity():

    hash_file = PATIENT_FILE + ".sha256"

    if not os.path.exists(hash_file):
        save_integrity_hash()
        return True

    with open(
        hash_file,
        "r",
        encoding="utf-8"
    ) as file:

        stored_hash = file.read().strip()

    current_hash = calculate_file_hash()

    return stored_hash == current_hash


# ============================================================
# SESSION / LOGIN HELPERS
# ============================================================

def current_user():

    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = get_db()

    user = conn.execute(
        """
        SELECT id, username, role
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    conn.close()

    return user


def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not current_user():
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def action_allowed(action):

    user = current_user()

    if not user:
        return False

    role = user["role"]

    return action in ROLE_ACTIONS.get(
        role,
        set()
    )


# ============================================================
# COMMON HTML
# ============================================================

STYLE = """

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Arial,
        sans-serif;

    background: #f5f7fb;
    color: #17213c;
}

a {
    text-decoration: none;
}

.topbar {
    background: #ffffff;
    border-bottom: 1px solid #e5e9f2;
    padding: 18px 6%;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
}

.logo {
    width: 46px;
    height: 46px;
    border-radius: 14px;
    background: #5b6ff0;
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 18px;
}

.brand-title {
    font-size: 20px;
    font-weight: 750;
}

.brand-subtitle {
    font-size: 13px;
    color: #7b87a5;
    margin-top: 2px;
}

.nav {
    display: flex;
    align-items: center;
    gap: 18px;
}

.nav a {
    color: #64708d;
    font-weight: 600;
}

.logout {
    color: #5969e8 !important;
}

.container {
    max-width: 1150px;
    margin: 0 auto;
    padding: 45px 25px 70px;
}

.welcome {
    margin-bottom: 28px;
}

.welcome h1 {
    font-size: 38px;
    margin: 0 0 8px;
}

.welcome p {
    color: #7b87a5;
    font-size: 16px;
}

.card {
    background: white;
    border: 1px solid #e4e8f1;
    border-radius: 20px;
    padding: 28px;
    margin-bottom: 25px;
    box-shadow: 0 8px 25px rgba(30, 45, 80, 0.04);
}

.card h2 {
    margin-top: 0;
    font-size: 24px;
}

.patient-header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding-bottom: 22px;
    border-bottom: 1px solid #edf0f5;
}

.patient-avatar {
    width: 55px;
    height: 55px;
    border-radius: 50%;
    background: #edf0ff;
    color: #5368ed;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 21px;
}

.patient-name {
    font-size: 21px;
    font-weight: 750;
}

.patient-id {
    color: #8b96ad;
    margin-top: 4px;
}

.details {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 22px;
    margin-top: 24px;
}

.detail-label {
    font-size: 12px;
    text-transform: uppercase;
    color: #8994ab;
    letter-spacing: 0.7px;
    margin-bottom: 6px;
}

.detail-value {
    font-weight: 650;
    color: #1b2946;
}

.document {
    border: 1px solid #e2e7f0;
    border-radius: 16px;
    padding: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.document-info {
    display: flex;
    align-items: center;
    gap: 15px;
}

.file-icon {
    width: 52px;
    height: 52px;
    border-radius: 14px;
    background: #edf0ff;
    color: #5268ee;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
}

.file-name {
    font-weight: 750;
    font-size: 17px;
}

.file-description {
    color: #8994ab;
    font-size: 14px;
    margin-top: 5px;
}

.button {
    border: 0;
    border-radius: 10px;
    padding: 11px 20px;
    background: #586cf0;
    color: white;
    font-weight: 700;
    cursor: pointer;
    font-size: 14px;
}

.button:hover {
    background: #465be1;
}

.button-secondary {
    background: white;
    color: #5365df;
    border: 1px solid #d9def0;
}

.button-secondary:hover {
    background: #f5f6ff;
}

textarea {
    width: 100%;
    min-height: 360px;
    border: 1px solid #dce2ee;
    border-radius: 14px;
    padding: 18px;
    font-family: Consolas, monospace;
    font-size: 14px;
    resize: vertical;
    outline: none;
}

textarea:focus {
    border-color: #6275ef;
    box-shadow: 0 0 0 3px rgba(98,117,239,0.10);
}

.actions {
    display: flex;
    gap: 12px;
    margin-top: 18px;
}

.alert {
    padding: 15px 18px;
    border-radius: 12px;
    margin-bottom: 20px;
    font-weight: 600;
}

.alert-error {
    background: #fff0f0;
    color: #c94b4b;
    border: 1px solid #f4cccc;
}

.alert-success {
    background: #eefaf4;
    color: #32865d;
    border: 1px solid #ccebdc;
}

.auth-page {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 25px;
    background: #f5f7fb;
}

.auth-card {
    width: 100%;
    max-width: 460px;
    background: white;
    border: 1px solid #e3e7ef;
    border-radius: 22px;
    padding: 40px;
    box-shadow: 0 15px 45px rgba(35, 48, 90, 0.08);
}

.auth-logo {
    margin-bottom: 25px;
}

.auth-card h1 {
    margin-bottom: 8px;
}

.auth-card p {
    color: #7c87a2;
}

.form-group {
    margin-bottom: 18px;
}

.form-group label {
    display: block;
    margin-bottom: 7px;
    font-weight: 650;
}

.form-group input,
.form-group select {
    width: 100%;
    padding: 13px 14px;
    border: 1px solid #dce2ed;
    border-radius: 11px;
    font-size: 15px;
    outline: none;
}

.form-group input:focus,
.form-group select:focus {
    border-color: #6275ef;
}

.full-button {
    width: 100%;
    padding: 14px;
    margin-top: 8px;
}

.auth-link {
    text-align: center;
    margin-top: 20px;
}

.auth-link a {
    color: #566be9;
    font-weight: 700;
}

.footer {
    text-align: center;
    color: #929db2;
    font-size: 13px;
    margin-top: 35px;
}

.badge {
    display: inline-block;
    background: #eef9f3;
    color: #37845d;
    padding: 7px 12px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 700;
}

@media (max-width: 700px) {

    .topbar {
        padding: 15px 20px;
    }

    .nav {
        gap: 8px;
    }

    .nav a:not(.logout) {
        display: none;
    }

    .container {
        padding: 30px 16px;
    }

    .welcome h1 {
        font-size: 30px;
    }

    .details {
        grid-template-columns: 1fr;
    }

    .document {
        align-items: flex-start;
        gap: 15px;
        flex-direction: column;
    }

    .document .button {
        width: 100%;
    }

    .auth-card {
        padding: 28px 22px;
    }
}

"""


# ============================================================
# BASE TEMPLATE
# ============================================================

BASE_START = """

<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>CareSecure Hospital Portal</title>

<style>
""" + STYLE + """
</style>

</head>

<body>

<header class="topbar">

    <div class="brand">

        <div class="logo">
            CS
        </div>

        <div>
            <div class="brand-title">
                CareSecure
            </div>

            <div class="brand-subtitle">
                Hospital Portal
            </div>
        </div>

    </div>

    <nav class="nav">

        {% if current_user %}
            <a href="{{ url_for('dashboard') }}">
                Home
            </a>

            <a
                href="{{ url_for('logout') }}"
                class="logout"
            >
                Log out
            </a>
        {% endif %}

    </nav>

</header>

<main class="container">

"""


BASE_END = """

</main>

<footer class="footer">

    CareSecure Hospital Portal • Educational demo using synthetic data

</footer>

</body>
</html>

"""


# ============================================================
# LOGIN PAGE
# ============================================================

LOGIN_HTML = """

<div class="auth-page">

    <div class="auth-card">

        <div class="brand auth-logo">

            <div class="logo">
                CS
            </div>

            <div>
                <div class="brand-title">
                    CareSecure
                </div>

                <div class="brand-subtitle">
                    Hospital Portal
                </div>
            </div>

        </div>

        <h1>Welcome back</h1>

        <p>
            Sign in to access your hospital records.
        </p>

        {% with messages = get_flashed_messages(with_categories=true) %}

            {% for category, message in messages %}

                <div class="alert alert-error">
                    {{ message }}
                </div>

            {% endfor %}

        {% endwith %}

        <form method="POST">

            <div class="form-group">

                <label>
                    Username
                </label>

                <input
                    type="text"
                    name="username"
                    placeholder="Enter username"
                    required
                >

            </div>

            <div class="form-group">

                <label>
                    Password
                </label>

                <input
                    type="password"
                    name="password"
                    placeholder="Enter password"
                    required
                >

            </div>

            <button
                class="button full-button"
                type="submit"
            >
                Sign in
            </button>

        </form>

        <div class="auth-link">

            Don't have an account?

            <a href="{{ url_for('register') }}">
                Create an account
            </a>

        </div>

    </div>

</div>

"""


# ============================================================
# REGISTER PAGE
# ============================================================

REGISTER_HTML = """

<div class="auth-page">

    <div class="auth-card">

        <div class="brand auth-logo">

            <div class="logo">
                CS
            </div>

            <div>

                <div class="brand-title">
                    CareSecure
                </div>

                <div class="brand-subtitle">
                    Hospital Portal
                </div>

            </div>

        </div>

        <h1>Create account</h1>

        <p>
            Register a new CareSecure account.
        </p>

        {% with messages = get_flashed_messages(with_categories=true) %}

            {% for category, message in messages %}

                <div class="alert alert-error">
                    {{ message }}
                </div>

            {% endfor %}

        {% endwith %}

        <form method="POST">

            <div class="form-group">

                <label>
                    Username
                </label>

                <input
                    type="text"
                    name="username"
                    placeholder="Choose a username"
                    required
                    minlength="3"
                >

            </div>

            <div class="form-group">

                <label>
                    Password
                </label>

                <input
                    type="password"
                    name="password"
                    placeholder="Create a password"
                    required
                    minlength="6"
                >

            </div>

            <div class="form-group">

                <label>
                    Account type
                </label>

                <select name="role">

                    <option value="Guest">
                        Patient / Guest
                    </option>

                    <option value="Nurse">
                        Nurse
                    </option>

                    <option value="Doctor">
                        Doctor
                    </option>

                </select>

            </div>

            <button
                class="button full-button"
                type="submit"
            >
                Create account
            </button>

        </form>

        <div class="auth-link">

            Already have an account?

            <a href="{{ url_for('login') }}">
                Sign in
            </a>

        </div>

    </div>

</div>

"""


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Incorrect username or password.",
            "error"
        )

    return render_template_string(
        LOGIN_HTML
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        role = request.form.get(
            "role",
            "Guest"
        )

        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        # Prevent users from creating arbitrary privileged roles.
        if role not in {
            "Doctor",
            "Nurse",
            "Guest"
        }:

            role = "Guest"

        password_hash = generate_password_hash(
            password
        )

        conn = get_db()

        try:

            conn.execute(
                """
                INSERT INTO users
                (
                    username,
                    password_hash,
                    role
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    role
                )
            )

            conn.commit()

        except sqlite3.IntegrityError:

            conn.close()

            flash(
                "That username is already registered.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        conn.close()

        flash(
            "Account created successfully. Please sign in.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template_string(
        REGISTER_HTML
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def index():

    if current_user():

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


@app.route("/dashboard")
@login_required
def dashboard():

    user = current_user()

    return render_template_string(
        BASE_START
        + """

<div class="welcome">

    <h1>
        Hello, {{ user["username"] }}.
    </h1>

    <p>
        Welcome to your CareSecure hospital portal.
        Your available records and documents are shown below.
    </p>

</div>


{% with messages = get_flashed_messages(with_categories=true) %}

    {% for category, message in messages %}

        <div
            class="alert
            {% if category == 'success' %}
                alert-success
            {% else %}
                alert-error
            {% endif %}"
        >
            {{ message }}
        </div>

    {% endfor %}

{% endwith %}


<div class="card">

    <div
        style="
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:25px;
        "
    >

        <div>

            <div class="detail-label">
                Health Information
            </div>

            <h2>
                Patient Records
            </h2>

            <p style="color:#7b87a5;">
                Your available patient information is displayed here.
            </p>

        </div>

        <span class="badge">
            Protected
        </span>

    </div>


    <div class="patient-header">

        <div class="patient-avatar">
            J
        </div>

        <div>

            <div class="patient-name">
                John Anderson
            </div>

            <div class="patient-id">
                P1001
            </div>

        </div>

    </div>


    <div class="details">

        <div>

            <div class="detail-label">
                Email
            </div>

            <div class="detail-value">
                john.anderson@example.com
            </div>

        </div>


        <div>

            <div class="detail-label">
                Phone
            </div>

            <div class="detail-value">
                416-555-0198
            </div>

        </div>


        <div>

            <div class="detail-label">
                Diagnosis
            </div>

            <div class="detail-value">
                Community-acquired pneumonia
            </div>

        </div>


        <div>

            <div class="detail-label">
                Doctor
            </div>

            <div class="detail-value">
                Dr. Sarah Williams
            </div>

        </div>


        <div>

            <div class="detail-label">
                Next Appointment
            </div>

            <div class="detail-value">
                2026-10-05 10:30
            </div>

        </div>

    </div>

</div>


<div class="card">

    <div class="detail-label">
        Documents
    </div>

    <h2>
        Available documents
    </h2>

    <p style="color:#7b87a5;">
        Select a document to view it.
    </p>


    <div class="document">

        <div class="document-info">

            <div class="file-icon">
                TXT
            </div>

            <div>

                <div class="file-name">
                    patient_record.txt
                </div>

                <div class="file-description">
                    Patient medical record
                </div>

            </div>

        </div>


        <a
            class="button button-secondary"
            href="{{ url_for('read_file', file_id=1) }}"
        >
            View
        </a>

    </div>

</div>

"""
        + BASE_END,

        user=user,
        current_user=user
    )


# ============================================================
# READ PATIENT RECORD
# ============================================================

@app.route("/file/<int:file_id>/read")
@login_required
def read_file(file_id):

    user = current_user()

    # Only the known patient record is available.
    if file_id != 1:

        return "File not found.", 404

    # Server-side access control.
    if not action_allowed("read"):

        flash(
            "You do not have permission to view this document.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    # SHA-256 integrity verification.
    if not verify_integrity():

        flash(
            "The document could not be verified because its integrity check failed.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    try:

        with open(
            PATIENT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            content = file.read()

    except Exception:

        flash(
            "The document could not be opened.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template_string(
        BASE_START
        + """

<div class="welcome">

    <h1>
        Patient Record
    </h1>

    <p>
        View the available patient information below.
    </p>

</div>


<div class="card">

    <div
        style="
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:20px;
        "
    >

        <div>

            <div class="detail-label">
                Document
            </div>

            <h2>
                patient_record.txt
            </h2>

        </div>

        <span class="badge">
            Protected
        </span>

    </div>


    <textarea readonly>{{ content }}</textarea>


    {% if can_write %}

        <div class="actions">

            <a
                class="button"
                href="{{ url_for('edit_file', file_id=1) }}"
            >
                Edit Record
            </a>

            <a
                class="button button-secondary"
                href="{{ url_for('dashboard') }}"
            >
                Back
            </a>

        </div>

    {% else %}

        <div class="actions">

            <a
                class="button button-secondary"
                href="{{ url_for('dashboard') }}"
            >
                Back
            </a>

        </div>

    {% endif %}

</div>

"""
        + BASE_END,

        user=user,
        current_user=user,
        content=content,
        can_write=action_allowed("write")
    )


# ============================================================
# EDIT PATIENT RECORD
# ============================================================

@app.route(
    "/file/<int:file_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_file(file_id):

    user = current_user()

    if file_id != 1:

        return "File not found.", 404

    # Only Doctor can write.
    if not action_allowed("write"):

        flash(
            "You do not have permission to edit this document.",
            "error"
        )

        return redirect(
            url_for(
                "read_file",
                file_id=1
            )
        )

    if request.method == "POST":

        content = request.form.get(
            "content",
            ""
        )

        try:

            with open(
                PATIENT_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(content)

            # Update integrity hash after legitimate modification.
            save_integrity_hash()

            flash(
                "Patient record updated successfully.",
                "success"
            )

            return redirect(
                url_for(
                    "read_file",
                    file_id=1
                )
            )

        except Exception:

            flash(
                "The patient record could not be updated.",
                "error"
            )

    else:

        try:

            with open(
                PATIENT_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                content = file.read()

        except Exception:

            content = ""

    return render_template_string(
        BASE_START
        + """

<div class="welcome">

    <h1>
        Edit Patient Record
    </h1>

    <p>
        Update the patient information below.
    </p>

</div>


<div class="card">

    <form method="POST">

        <textarea
            name="content"
            required
        >{{ content }}</textarea>


        <div class="actions">

            <button
                class="button"
                type="submit"
            >
                Save Changes
            </button>

            <a
                class="button button-secondary"
                href="{{ url_for('read_file', file_id=1) }}"
            >
                Cancel
            </a>

        </div>

    </form>

</div>

"""
        + BASE_END,

        user=user,
        current_user=user,
        content=content
    )


# ============================================================
# APPLICATION STARTUP
# ============================================================

if __name__ == "__main__":

    init_database()

    initialize_patient_file()

    # Create the initial integrity hash
    # if it does not already exist.
    hash_file = PATIENT_FILE + ".sha256"

    if not os.path.exists(hash_file):

        save_integrity_hash()

    print()
    print("==========================================")
    print("       CareSecure Hospital Lab 3")
    print("==========================================")
    print()
    print("Open: http://127.0.0.1:5000")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )