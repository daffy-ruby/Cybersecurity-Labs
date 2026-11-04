import time
import pyotp
from secure_auth_system import UnifiedAuthSystem
from totp_manager import GoogleAuthenticatorManager

def run_live_test():
    print("=" * 60)
    print("      LIVE END-TO-END SYSTEM INTEGRATION TEST       ")
    print("=" * 60)

    auth = UnifiedAuthSystem()
    totp_mgr = GoogleAuthenticatorManager(issuer_name="LiveTestApp")

    # TEST 1: User Registration
    print("\n[TEST 1] Registration & Password Validation")
    username = "test_user_2026"
    
    uid, msg = auth.register_user(username, "test1234")
    print(f" -> Weak Pass Reg: {msg}")

    strong_pass = "P@ssword!2026#Secure"
    uid, msg = auth.register_user(username, strong_pass)
    print(f" -> Strong Pass Reg: {msg}")
    
    if not uid:
        print("[FAIL] Registration failed. Aborting test.")
        return

    # TEST 2: Google Authenticator Setup
    print("\n[TEST 2] Google Authenticator Setup")
    user_secret = totp_mgr.generate_user_secret()
    
    shadow_db = auth._load_data(auth.shadow_file)
    shadow_db[uid]["totp_secret"] = user_secret
    auth._save_data(auth.shadow_file, shadow_db)
    
    totp_mgr.get_setup_qr(username, user_secret, save_filename="user_qr.png")
    print(f" -> Generated Secret Key: {user_secret}")

    # TEST 3: Login & TOTP
    print("\n[TEST 3] Multi-Factor Authentication Login Flow")
    success, initial_token, login_msg = auth.login(uid, strong_pass)
    print(f" -> Primary Password Step: {login_msg}")

    totp_generator = pyotp.TOTP(user_secret)
    live_code = totp_generator.now()
    totp_valid = totp_mgr.verify_code(user_secret, live_code)
    print(f" -> Generated 6-Digit App Code: {live_code}")
    print(f" -> TOTP Verification Result: {'PASSED' if totp_valid else 'FAILED'}")

    # TEST 4: Rate Limiting
    print("\n[TEST 4] Brute Force Rate Limiting")
    for i in range(1, 5):
        allowed, token, err_msg = auth.login(uid, "WrongPassword123!")
        print(f"    Attempt {i}: {err_msg}")

    # TEST 5: Password Reset & History Violation
    print("\n[TEST 5] Password Reset & Re-use Prevention")
    reset_ok, reset_msg = auth.reset_password(uid, strong_pass)
    print(f" -> Re-use Old Password: {reset_msg}")

    brand_new_pass = "N3w_B3tter_P@ss2026!"
    reset_ok, reset_msg = auth.reset_password(uid, brand_new_pass)
    print(f" -> Use Unique New Password: {reset_msg}")

    # TEST 6: Emergency Panic Mode
    print("\n[TEST 6] Emergency Lockdown & Token Revocation")
    val_ok, val_msg = auth.validate_token(initial_token)
    print(f" -> Access Token Status Before Lockdown: {val_msg}")

    auth.trigger_emergency_shutdown(reason="Automated Threat Response Triggered")

    val_ok, val_msg = auth.validate_token(initial_token)
    print(f" -> Access Token Status After Lockdown: {val_msg}")

if __name__ == "__main__":
    run_live_test()