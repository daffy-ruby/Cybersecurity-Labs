import bcrypt
import json
import hashlib
import re
import secrets
import pyotp
import qrcode

from datetime import datetime, timedelta
from getpass import getpass
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

USERS_FILE = Path("users.json")
LOG_FILE = Path("login_logs.txt")
OTP_FILE = Path("otp_store.txt")

MAX_FAILED_ATTEMPTS = 5

# File-based OTP settings
OTP_EXPIRY_SECONDS = 30
MAX_OTP_ATTEMPTS = 3

# Google Authenticator settings
MAX_AUTHENTICATOR_ATTEMPTS = 3
AUTHENTICATOR_INTERVAL = 30


# ============================================================
# FILE FUNCTIONS
# ============================================================

def load_users():
    if not USERS_FILE.exists():
        return {}

    try:
        with open(USERS_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        return {}


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)


# ============================================================
# LOGGING
# ============================================================

def log_event(email, event):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(
            f"{timestamp} | {email} | {event}\n"
        )


# ============================================================
# EMAIL VALIDATION
# ============================================================

def is_valid_email(email):
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None


# ============================================================
# PASSWORD VALIDATION
# ============================================================

def is_valid_password(password):

    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[0-9]", password):
        return False

    return True


# ============================================================
# SHA-256 INTEGRITY
# ============================================================

def calculate_integrity_hash(record):

    data = {
        key: value
        for key, value in record.items()
        if key != "integrity_hash"
    }

    json_data = json.dumps(
        data,
        sort_keys=True
    )

    return hashlib.sha256(
        json_data.encode("utf-8")
    ).hexdigest()


def verify_record_integrity(record):

    stored_hash = record.get("integrity_hash")

    if not stored_hash:
        return False

    calculated_hash = calculate_integrity_hash(record)

    return stored_hash == calculated_hash


# ============================================================
# REGISTER USER
# ============================================================

def register_user():

    print("\n========== USER REGISTRATION ==========")

    users = load_users()

    email = input(
        "Enter email address: "
    ).strip().lower()

    if not is_valid_email(email):

        print("Invalid email address.")
        print("Please enter a valid email ID.")

        return

    if email in users:

        print(
            "An account with this email already exists."
        )

        return

    password = getpass(
        "Create password: "
    )

    if not is_valid_password(password):

        print("\nPassword does not meet security requirements.")

        print("Password must contain:")
        print("- At least 8 characters")
        print("- At least one uppercase letter")
        print("- At least one lowercase letter")
        print("- At least one number")

        return

    confirm_password = getpass(
        "Confirm password: "
    )

    if password != confirm_password:

        print("Passwords do not match.")

        return

    # ========================================================
    # BCRYPT PASSWORD HASHING
    # ========================================================

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # ========================================================
    # USER RECORD
    # ========================================================

    user_record = {

        "password_hash": password_hash,

        "failed_attempts": 0,

        "locked": False,

        # Google Authenticator
        "authenticator_secret": None,

        # Prevent reuse of same TOTP code
        "last_used_totp_counter": None
    }

    # ========================================================
    # INTEGRITY HASH
    # ========================================================

    user_record["integrity_hash"] = calculate_integrity_hash(
        user_record
    )

    users[email] = user_record

    save_users(users)

    log_event(
        email,
        "REGISTRATION_SUCCESS"
    )

    print("\nRegistration successful.")
    print("Password stored securely using bcrypt.")
    print("Account created successfully.")


# ============================================================
# FILE-BASED OTP
# ============================================================

def generate_file_otp(email):

    # Secure random 6-digit OTP
    otp = f"{secrets.randbelow(1000000):06d}"

    # Expiration
    expiry_time = (
        datetime.now()
        + timedelta(seconds=OTP_EXPIRY_SECONDS)
    )

    otp_data = {

        "email": email,

        "otp": otp,

        "expires": expiry_time.isoformat(),

        "used": False
    }

    # Save to otp_store.txt
    with open(
        OTP_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        for key, value in otp_data.items():

            file.write(
                f"{key}={value}\n"
            )

    log_event(
        email,
        "FILE_OTP_GENERATED"
    )

    print("\n========== FILE-BASED OTP ==========")

    print("Secure 6-digit OTP generated.")

    print("OTP stored in otp_store.txt.")

    print(
        f"OTP expires in {OTP_EXPIRY_SECONDS} seconds."
    )

    # For the college lab demonstration
    print(
        f"\nYour File-Based OTP is: {otp}"
    )

    return otp_data


# ============================================================
# READ OTP FILE
# ============================================================

def read_otp_file():

    if not OTP_FILE.exists():

        return None

    otp_data = {}

    try:

        with open(
            OTP_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if "=" in line:

                    key, value = line.split(
                        "=",
                        1
                    )

                    otp_data[key] = value

        return otp_data

    except OSError:

        return None


# ============================================================
# INVALIDATE FILE OTP
# ============================================================

def invalidate_file_otp():

    if OTP_FILE.exists():

        try:

            OTP_FILE.unlink()

        except OSError:

            pass


# ============================================================
# VERIFY FILE OTP
# ============================================================

def verify_file_otp(email):

    print(
        "\n========== FILE OTP VERIFICATION =========="
    )

    otp_data = read_otp_file()

    if otp_data is None:

        print("No OTP is available.")

        return False

    # Check email
    if otp_data.get("email") != email:

        print("OTP does not belong to this user.")

        log_event(
            email,
            "FILE_OTP_USER_MISMATCH"
        )

        return False

    # Check used status
    if otp_data.get("used") == "True":

        print("This OTP has already been used.")

        log_event(
            email,
            "FILE_OTP_REUSE_ATTEMPT"
        )

        invalidate_file_otp()

        return False

    # ========================================================
    # CHECK EXPIRATION
    # ========================================================

    try:

        expiry_time = datetime.fromisoformat(
            otp_data["expires"]
        )

    except (KeyError, ValueError):

        print("Invalid OTP expiration data.")

        invalidate_file_otp()

        return False

    if datetime.now() > expiry_time:

        print("OTP has expired.")

        log_event(
            email,
            "FILE_OTP_EXPIRED"
        )

        invalidate_file_otp()

        return False

    # ========================================================
    # ATTEMPTS
    # ========================================================

    attempts = 0

    while attempts < MAX_OTP_ATTEMPTS:

        entered_otp = input(
            "\nEnter File-Based OTP: "
        ).strip()

        # Check expiration again
        if datetime.now() > expiry_time:

            print("OTP has expired.")

            log_event(
                email,
                "FILE_OTP_EXPIRED"
            )

            invalidate_file_otp()

            return False

        # Correct OTP
        if entered_otp == otp_data.get("otp"):

            otp_data["used"] = "True"

            with open(
                OTP_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                for key, value in otp_data.items():

                    file.write(
                        f"{key}={value}\n"
                    )

            log_event(
                email,
                "FILE_OTP_VERIFICATION_SUCCESS"
            )

            print("\nFile-Based OTP verified successfully.")

            # Prevent reuse
            invalidate_file_otp()

            return True

        # Incorrect OTP
        attempts += 1

        remaining = (
            MAX_OTP_ATTEMPTS - attempts
        )

        log_event(
            email,
            "FILE_OTP_VERIFICATION_FAILED"
        )

        if remaining > 0:

            print("\nIncorrect OTP.")

            print(
                f"Attempts remaining: {remaining}"
            )

        else:

            print(
                "\nMaximum OTP attempts reached."
            )

            print(
                "OTP has been invalidated."
            )

            log_event(
                email,
                "FILE_OTP_LOCKED"
            )

            invalidate_file_otp()

            return False

    return False


# ============================================================
# GOOGLE AUTHENTICATOR SETUP
# ============================================================

def setup_google_authenticator(email):

    users = load_users()

    user = users[email]

    # Already configured
    if user.get("authenticator_secret"):

        print(
            "\nGoogle Authenticator is already configured."
        )

        return True

    # Generate secure secret
    secret = pyotp.random_base32()

    user["authenticator_secret"] = secret

    user["last_used_totp_counter"] = None

    # Update integrity hash
    user["integrity_hash"] = calculate_integrity_hash(
        user
    )

    users[email] = user

    save_users(users)

    # Create provisioning URI
    totp = pyotp.TOTP(
        secret,
        interval=AUTHENTICATOR_INTERVAL
    )

    provisioning_uri = totp.provisioning_uri(
        name=email,
        issuer_name="Lab 2 Secure Authentication"
    )

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4
    )

    qr.add_data(provisioning_uri)

    qr.make(
        fit=True
    )

    qr_image = qr.make_image()

    qr_file = Path(
        f"google_authenticator_{email.replace('@', '_at_').replace('.', '_')}.png"
    )

    qr_image.save(qr_file)

    log_event(
        email,
        "GOOGLE_AUTHENTICATOR_SETUP"
    )

    print(
        "\n========== GOOGLE AUTHENTICATOR SETUP =========="
    )

    print(
        "\nQR code created successfully."
    )

    print(
        f"QR code saved as:\n{qr_file}"
    )

    print(
        "\nOpen this PNG image and scan it using Google Authenticator."
    )

    print(
        "\nSteps:"
    )

    print(
        "1. Open Google Authenticator on your phone."
    )

    print(
        "2. Select + / Add account."
    )

    print(
        "3. Select Scan a QR code."
    )

    print(
        "4. Scan the generated QR code."
    )

    print(
        "5. Google Authenticator will generate a 6-digit code."
    )

    return True


# ============================================================
# GOOGLE AUTHENTICATOR VERIFICATION
# ============================================================

def verify_google_authenticator(email):

    print(
        "\n========== GOOGLE AUTHENTICATOR =========="
    )

    users = load_users()

    user = users.get(email)

    if not user:

        print("User not found.")

        return False

    secret = user.get(
        "authenticator_secret"
    )

    if not secret:

        print(
            "Google Authenticator is not configured."
        )

        return False

    totp = pyotp.TOTP(
        secret,
        interval=AUTHENTICATOR_INTERVAL
    )

    attempts = 0

    while attempts < MAX_AUTHENTICATOR_ATTEMPTS:

        code = input(
            "\nEnter the 6-digit code from Google Authenticator: "
        ).strip()

        # Current TOTP time counter
        current_counter = (
            int(datetime.now().timestamp())
            // AUTHENTICATOR_INTERVAL
        )

        # Prevent same code/time-period reuse
        last_counter = user.get(
            "last_used_totp_counter"
        )

        if last_counter == current_counter:

            print(
                "\nThis authenticator code has already been used."
            )

            log_event(
                email,
                "AUTHENTICATOR_REUSE_ATTEMPT"
            )

            return False

        # Verify TOTP
        if totp.verify(
            code,
            valid_window=0
        ):

            # Save current counter
            user["last_used_totp_counter"] = current_counter

            # Update integrity hash
            user["integrity_hash"] = calculate_integrity_hash(
                user
            )

            users[email] = user

            save_users(users)

            log_event(
                email,
                "GOOGLE_AUTHENTICATOR_SUCCESS"
            )

            print(
                "\nGoogle Authenticator code verified successfully."
            )

            return True

        attempts += 1

        remaining = (
            MAX_AUTHENTICATOR_ATTEMPTS - attempts
        )

        log_event(
            email,
            "GOOGLE_AUTHENTICATOR_FAILED"
        )

        print(
            "\nIncorrect authenticator code."
        )

        if remaining > 0:

            print(
                f"Attempts remaining: {remaining}"
            )

        else:

            print(
                "Maximum authenticator attempts reached."
            )

            return False

    return False


# ============================================================
# MFA MENU
# ============================================================

def perform_mfa(email):

    print(
        "\n=========================================="
    )

    print(
        "       MULTI-FACTOR AUTHENTICATION"
    )

    print(
        "=========================================="
    )

    print(
        "\nChoose MFA method:"
    )

    print(
        "1. File-Based OTP"
    )

    print(
        "2. Google Authenticator"
    )

    print(
        "3. Setup Google Authenticator"
    )

    choice = input(
        "\nEnter your choice: "
    ).strip()

    # ========================================================
    # FILE OTP
    # ========================================================

    if choice == "1":

        generate_file_otp(email)

        return verify_file_otp(email)

    # ========================================================
    # GOOGLE AUTHENTICATOR
    # ========================================================

    elif choice == "2":

        users = load_users()

        if not users[email].get(
            "authenticator_secret"
        ):

            print(
                "\nGoogle Authenticator is not configured yet."
            )

            print(
                "Please choose option 3 first."
            )

            return False

        return verify_google_authenticator(email)

    # ========================================================
    # SETUP GOOGLE AUTHENTICATOR
    # ========================================================

    elif choice == "3":

        setup_google_authenticator(email)

        print(
            "\nSetup completed."
        )

        print(
            "Run Login again and choose option 2 "
            "to verify using Google Authenticator."
        )

        return False

    else:

        print(
            "Invalid MFA option."
        )

        return False


# ============================================================
# LOGIN
# ============================================================

def login_user():

    print(
        "\n========== USER LOGIN =========="
    )

    users = load_users()

    email = input(
        "Enter email address: "
    ).strip().lower()

    if not is_valid_email(email):

        print(
            "Invalid email address."
        )

        return False

    if email not in users:

        print(
            "Invalid email or password."
        )

        log_event(
            email,
            "LOGIN_FAILED_UNKNOWN_USER"
        )

        return False

    user = users[email]

    # ========================================================
    # INTEGRITY CHECK
    # ========================================================

    if not verify_record_integrity(user):

        print(
            "\nWARNING: User record integrity check failed."
        )

        print(
            "The user record may have been modified."
        )

        log_event(
            email,
            "INTEGRITY_CHECK_FAILED"
        )

        return False

    # ========================================================
    # ACCOUNT LOCK CHECK
    # ========================================================

    if user.get("locked") is True:

        print(
            "\nAccount locked. "
            "Please reach out to an administrator."
        )

        log_event(
            email,
            "LOGIN_DENIED_ACCOUNT_LOCKED"
        )

        return False

    # ========================================================
    # PASSWORD
    # ========================================================

    password = getpass(
        "Enter password: "
    )

    stored_hash = user["password_hash"]

    try:

        password_correct = bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash.encode("utf-8")
        )

    except ValueError:

        print(
            "Stored password hash is invalid."
        )

        log_event(
            email,
            "INVALID_PASSWORD_HASH"
        )

        return False

    # ========================================================
    # PASSWORD SUCCESS
    # ========================================================

    if password_correct:

        user["failed_attempts"] = 0

        user["integrity_hash"] = calculate_integrity_hash(
            user
        )

        users[email] = user

        save_users(users)

        log_event(
            email,
            "PASSWORD_VERIFICATION_SUCCESS"
        )

        print(
            "\nLogin successful."
        )

        print(
            "Password verified successfully."
        )

        # ====================================================
        # MFA
        # ====================================================

        mfa_success = perform_mfa(email)

        if mfa_success:

            print(
                "\n=========================================="
            )

            print(
                "MFA authentication successful."
            )

            print(
                "User authentication completed successfully."
            )

            print(
                "=========================================="
            )

            log_event(
                email,
                "MFA_AUTHENTICATION_SUCCESS"
            )

            return True

        else:

            print(
                "\nMFA authentication failed."
            )

            log_event(
                email,
                "MFA_AUTHENTICATION_FAILED"
            )

            return False

    # ========================================================
    # PASSWORD FAILURE
    # ========================================================

    else:

        user["failed_attempts"] = (
            user.get("failed_attempts", 0) + 1
        )

        failed_attempts = user["failed_attempts"]

        # Lock after 5 attempts
        if failed_attempts >= MAX_FAILED_ATTEMPTS:

            user["locked"] = True

            user["integrity_hash"] = calculate_integrity_hash(
                user
            )

            users[email] = user

            save_users(users)

            print(
                "\nPassword incorrect."
            )

            print(
                "Maximum failed login attempts reached."
            )

            print(
                "Account locked."
            )

            print(
                "Please reach out to an administrator."
            )

            log_event(
                email,
                "ACCOUNT_LOCKED"
            )

            return False

        user["integrity_hash"] = calculate_integrity_hash(
            user
        )

        users[email] = user

        save_users(users)

        remaining = (
            MAX_FAILED_ATTEMPTS - failed_attempts
        )

        print(
            "\nPassword incorrect."
        )

        print(
            f"Failed attempts: "
            f"{failed_attempts}/{MAX_FAILED_ATTEMPTS}"
        )

        print(
            f"Attempts remaining: {remaining}"
        )

        log_event(
            email,
            "PASSWORD_VERIFICATION_FAILED"
        )

        return False


# ============================================================
# MAIN MENU
# ============================================================

def main():

    while True:

        print(
            "\n======================================"
        )

        print(
            "       SECURE AUTHENTICATION SYSTEM"
        )

        print(
            "======================================"
        )

        print(
            "1. Register"
        )

        print(
            "2. Login"
        )

        print(
            "3. Exit"
        )

        choice = input(
            "Choose an option: "
        ).strip()

        if choice == "1":

            register_user()

        elif choice == "2":

            login_user()

        elif choice == "3":

            print(
                "\nExiting Secure Authentication System."
            )

            break

        else:

            print(
                "Invalid option. "
                "Please choose 1, 2, or 3."
            )


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":
    main()