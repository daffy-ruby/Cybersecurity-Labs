import os
import secrets
import time
import warnings
import pyotp
from secure_auth_system import UnifiedAuthSystem
from totp_manager import GoogleAuthenticatorManager

# Suppress PyJWT key length warning shown in terminal
warnings.filterwarnings("ignore", category=UserWarning, module="jwt")

# =========================================================
# OTP DELIVERY FUNCTION (Terminal Display)
# =========================================================
def send_otp_via_gmail(recipient_email, otp_code):
    """Simulates OTP delivery by printing directly to the terminal."""
    print(f"\n[OTP DELIVERED TO TERMINAL]: {otp_code}")
    return True

# =========================================================
# FILE-BASED OTP MANAGER (TASK 2 COMPLIANCE)
# =========================================================
class FileBasedOTPManager:
    def __init__(self, otp_file="otp_store.txt", ttl_seconds=60, max_attempts=3):
        self.otp_file = otp_file
        self.ttl_seconds = ttl_seconds
        self.max_attempts = max_attempts

    def generate_and_store_otp(self, username):
        """Generates a secure 6-digit OTP and writes to otp_store.txt."""
        otp_code = f"{secrets.randbelow(1000000):06d}"
        expires_at = time.time() + self.ttl_seconds

        with open(self.otp_file, "w") as f:
            f.write(f"{username},{otp_code},{expires_at},0\n")

        print(f"[TASK 2 OTP GENERATED] Saved to file: '{self.otp_file}' (Valid for {self.ttl_seconds}s)")
        return otp_code

    def verify_otp(self, username, input_code):
        """Validates OTP, checks expiration window, and enforces max attempts."""
        if not os.path.exists(self.otp_file):
            return False, "No active OTP found in store file."

        with open(self.otp_file, "r") as f:
            line = f.readline().strip()

        if not line:
            return False, "OTP store file is empty."

        stored_user, stored_otp, expires_at, attempts = line.split(",")
        expires_at = float(expires_at)
        attempts = int(attempts)

        if stored_user != username:
            return False, "Session user mismatch."

        if time.time() > expires_at:
            os.remove(self.otp_file)
            return False, "OTP has expired. Please log in again."

        if attempts >= self.max_attempts:
            os.remove(self.otp_file)
            return False, "Maximum failed attempts reached. OTP invalidated."

        if secrets.compare_digest(stored_otp, input_code):
            os.remove(self.otp_file)
            return True, "File-based OTP verified successfully!"
        else:
            attempts += 1
            with open(self.otp_file, "w") as f:
                f.write(f"{stored_user},{stored_otp},{expires_at},{attempts}\n")
            return False, f"Invalid OTP code. Attempts remaining: {self.max_attempts - attempts}"

# =========================================================
# MAIN INTERACTIVE PROGRAM
# =========================================================
def main():
    auth = UnifiedAuthSystem()
    totp_mgr = GoogleAuthenticatorManager(issuer_name="Task2App")
    file_otp_mgr = FileBasedOTPManager(ttl_seconds=60, max_attempts=3)

    print("==================================================")
    print("      LAB 2 SECURE AUTHENTICATION SYSTEM         ")
    print("==================================================")

    # 1. USER REGISTRATION (Prompting for Email & Duplicate Check)
    email_address = ""
    while True:
        print("\n--- STEP 1: REGISTER NEW USER ---")
        username = input("Enter Username: ").strip()
        email_address = input("Enter Email Address: ").strip()
        password = input("Enter Password: ").strip()

        # Check if the email address is already registered in shadow_db BEFORE registration
        shadow_db = auth._load_data(auth.shadow_file)
        existing_emails = [user_data.get("email") for user_data in shadow_db.values() if isinstance(user_data, dict)]

        if email_address in existing_emails:
            print("\n[REGISTRATION RESULT] Registration failed: Email address already exists.")
            print("--> Please try again with a different email address.")
            continue

        # Register user if email is unique
        uid, reg_msg = auth.register_user(username, password)
        print(f"\n[REGISTRATION RESULT] {reg_msg}")

        if uid:
            break
        print("--> Please try again with a different username or stronger password.")

    # Provision TOTP secret in background
    shadow_db = auth._load_data(auth.shadow_file)
    totp_secret = totp_mgr.generate_user_secret()
    shadow_db[uid]["totp_secret"] = totp_secret
    shadow_db[uid]["email"] = email_address
    auth._save_data(auth.shadow_file, shadow_db)
    totp_mgr.get_setup_qr(username, totp_secret, save_filename=f"qr_{uid}.png")

    # 2. PRIMARY PASSWORD LOGIN
    print("\n--- STEP 2: PRIMARY PASSWORD LOGIN ---")
    input_uid = input(f"Enter Numeric UID (Assigned: {uid}): ").strip()
    input_pass = input("Enter Password: ").strip()

    login_ok, token, login_msg = auth.login(input_uid, input_pass)
    print(f"\n[LOGIN STEP 1] {login_msg}")

    if not login_ok:
        return

    # 3. SELECT 2FA METHOD
    print("\n--- STEP 3: SELECT 2FA METHOD ---")
    print("1. File-Based OTP + Email Delivery (Lab Task 2 Requirement)")
    print("2. Google Authenticator (TOTP App Code)")
    choice = input("Select Option (1 or 2): ").strip()

    mfa_ok = False
    mfa_msg = ""

    if choice == "1":
        # Generate, write to file, and display code
        otp_code = file_otp_mgr.generate_and_store_otp(username)
        send_otp_via_gmail(email_address, otp_code)

        user_otp = input(f"\nEnter the 6-digit OTP code sent to '{email_address}': ").strip()
        mfa_ok, mfa_msg = file_otp_mgr.verify_otp(username, user_otp)
        print(f"\n[MFA RESULT] {mfa_msg}")

    elif choice == "2":
        live_app_code = pyotp.TOTP(totp_secret).now()
        print(f"\n[TOTP SECRET]: {totp_secret}")
        print(f"[CURRENT LIVE APP CODE]: {live_app_code}")

        user_totp = input("\nEnter 6-digit code from Google Authenticator App: ").strip()
        if totp_mgr.verify_code(totp_secret, user_totp):
            mfa_ok, mfa_msg = True, "Google Authenticator TOTP verified successfully!"
        else:
            mfa_ok, mfa_msg = False, "Invalid TOTP code."
        print(f"\n[MFA RESULT] {mfa_msg}")
    else:
        print("Invalid selection.")
        return

    # 4. TOKEN ISSUANCE & STORAGE
    if mfa_ok:
        with open("tokens.txt", "a") as f:
            f.write(f"UID: {uid} | Token: {token} | IssuedAt: {time.ctime()}\n")

        print("\n==================================================")
        print("      AUTHENTICATION SUCCESSFUL - ACCESS GRANTED  ")
        print("==================================================")
        print(f"Session Token: {token}")
        print("[TOKEN SAVED] Saved session token to 'tokens.txt'")

if __name__ == "__main__":
    main()