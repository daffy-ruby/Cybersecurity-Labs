import hashlib
import json
from pathlib import Path


# --------------------------------------------------
# FILE LOCATIONS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

ORIGINAL_FILE = BASE_DIR / "users.json"
TAMPERED_FILE = BASE_DIR / "users_tampered.json"


# --------------------------------------------------
# LOAD JSON FILE
# --------------------------------------------------

def load_json(file_path):
    """Load records from a JSON file."""

    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


# --------------------------------------------------
# CREATE SHA-256 HASH
# --------------------------------------------------

def record_hash(record):
    """Create a SHA-256 hash for a record."""

    data = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():

    print("=" * 60)
    print("TASK 4 - DATA TAMPER DETECTION")
    print("=" * 60)

    # Check original file
    if not ORIGINAL_FILE.exists():
        print("[ERROR] users.json was not found.")
        return

    # Check tampered file
    if not TAMPERED_FILE.exists():
        print("[ERROR] users_tampered.json was not found.")
        return

    # Load both files
    original_records = load_json(ORIGINAL_FILE)
    tampered_records = load_json(TAMPERED_FILE)

    print(f"[INFO] Original records: {len(original_records)}")
    print(f"[INFO] Tampered-file records: {len(tampered_records)}")

    # Create dictionaries using username
    original_by_username = {
        record["username"]: record
        for record in original_records
    }

    tampered_by_username = {
        record["username"]: record
        for record in tampered_records
    }

    modified_records = []

    # --------------------------------------------------
    # COMPARE RECORDS
    # --------------------------------------------------

    for username, original_record in original_by_username.items():

        tampered_record = tampered_by_username.get(username)

        # Record missing
        if tampered_record is None:

            modified_records.append(
                (username, "record missing")
            )

            continue

        # Calculate hashes
        original_hash = record_hash(original_record)
        tampered_hash = record_hash(tampered_record)

        # Compare hashes
        if original_hash != tampered_hash:

            modified_records.append(
                (username, "record modified")
            )

    # Check for newly added records
    for username in tampered_by_username:

        if username not in original_by_username:

            modified_records.append(
                (username, "new record added")
            )

    # --------------------------------------------------
    # DISPLAY RESULT
    # --------------------------------------------------

    if modified_records:

        print("\n[PASS] Tampering detected.")

        print("[INFO] Modified records:")

        for username, reason in modified_records:

            print(
                f"       - {username}: {reason}"
            )

        # Specifically show Bob's changed password
        if (
            "bob" in original_by_username
            and "bob" in tampered_by_username
        ):

            original_password = original_by_username[
                "bob"
            ].get("password")

            tampered_password = tampered_by_username[
                "bob"
            ].get("password")

            if original_password != tampered_password:

                print(
                    "\n[INFO] Bob's password differs "
                    "between the files."
                )

                print(
                    f"       Original : {original_password}"
                )

                print(
                    f"       Tampered : {tampered_password}"
                )

    else:

        print("\n[PASS] No tampering detected.")

    print("\n[INFO] Integrity comparison completed.")


# --------------------------------------------------
# START PROGRAM
# --------------------------------------------------

if __name__ == "__main__":
    main()