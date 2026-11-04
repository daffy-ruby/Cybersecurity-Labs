from cryptography.fernet import Fernet
import hashlib
import json
from pathlib import Path


# --------------------------------------------------
# FILE NAMES
# --------------------------------------------------

USERS_FILE = Path("users.json")
SECURE_FILE = Path("users_secure.json")
KEY_FILE = Path("secret.key")


# --------------------------------------------------
# LOAD OR CREATE ENCRYPTION KEY
# --------------------------------------------------

def load_or_create_key():
    """Load the encryption key or create a new one."""

    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()

    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)

    return key


# --------------------------------------------------
# CREATE SHA-256 INTEGRITY HASH
# --------------------------------------------------

def create_hash(record):
    """Create a SHA-256 hash for a user record."""

    data = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------
# LOAD USERS.JSON
# --------------------------------------------------

def load_users():
    """Load the supplied users.json file."""

    if not USERS_FILE.exists():
        print("[ERROR] users.json was not found.")
        return []

    try:
        with USERS_FILE.open("r", encoding="utf-8") as file:
            users = json.load(file)

        print(f"[INFO] Loaded {len(users)} records from users.json.")

        return users

    except json.JSONDecodeError:
        print("[ERROR] users.json contains invalid JSON.")
        return []


# --------------------------------------------------
# ENCRYPT PASSWORDS AND CREATE HASHES
# --------------------------------------------------

def create_secure_records(users, cipher):
    """Encrypt passwords and create integrity hashes."""

    secure_records = []

    for user in users:

        username = user.get("username", "")
        email = user.get("email", "")
        password = user.get("password", "")

        # Encrypt password
        encrypted_password = cipher.encrypt(
            password.encode("utf-8")
        ).decode("utf-8")

        # Create secure record
        record = {
            "username": username,
            "email": email,
            "encrypted_password": encrypted_password
        }

        # Create SHA-256 integrity hash
        record["integrity_hash"] = create_hash(record)

        secure_records.append(record)

    return secure_records


# --------------------------------------------------
# SAVE SECURE DATA
# --------------------------------------------------

def save_secure_users(users):
    """Save encrypted user records to users_secure.json."""

    with SECURE_FILE.open("w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)

    print("[PASS] Secure records saved to users_secure.json.")


# --------------------------------------------------
# VERIFY INTEGRITY
# --------------------------------------------------

def verify_integrity():
    """Verify that stored records have not been modified."""

    print("\n--- Integrity Verification ---")

    if not SECURE_FILE.exists():
        print("[ERROR] users_secure.json was not found.")
        return

    try:
        with SECURE_FILE.open("r", encoding="utf-8") as file:
            users = json.load(file)

    except json.JSONDecodeError:
        print("[ERROR] users_secure.json contains invalid JSON.")
        return

    all_valid = True

    for user in users:

        stored_hash = user.get("integrity_hash")

        # Recreate the record without the hash
        record_without_hash = {
            "username": user.get("username", ""),
            "email": user.get("email", ""),
            "encrypted_password": user.get(
                "encrypted_password", ""
            )
        }

        # Calculate a new hash
        calculated_hash = create_hash(record_without_hash)

        # Compare hashes
        if stored_hash == calculated_hash:

            print(
                f"[PASS] {user.get('username')}: "
                "Integrity verified."
            )

        else:

            print(
                f"[FAIL] {user.get('username')}: "
                "Data has been modified."
            )

            all_valid = False

    if all_valid:

        print("\n[PASS] All records passed integrity verification.")

    else:

        print(
            "\n[FAIL] One or more records failed "
            "integrity verification."
        )


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():

    print("=" * 60)
    print("TASK 2 - SECURE DATA STORAGE")
    print("=" * 60)

    # Step 1: Load users.json
    users = load_users()

    if not users:
        return

    # Step 2: Load/create encryption key
    key = load_or_create_key()

    # Step 3: Create Fernet encryption object
    cipher = Fernet(key)

    # Step 4: Encrypt passwords and create hashes
    secure_users = create_secure_records(
        users,
        cipher
    )

    # Step 5: Save secure records
    save_secure_users(secure_users)

    print("[PASS] Passwords encrypted using Fernet.")
    print("[PASS] SHA-256 integrity hash created for each record.")

    # Step 6: Verify integrity
    verify_integrity()


# --------------------------------------------------
# START PROGRAM
# --------------------------------------------------

if __name__ == "__main__":
    main()