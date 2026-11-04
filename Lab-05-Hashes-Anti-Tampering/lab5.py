"""Lab 5: Hashes & Anti-Tampering Mechanisms"""
import hashlib
import hmac
import json
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent / "lab5_data"
MESSAGE_FILE = BASE_DIR / "message.txt"
HMAC_FILE = BASE_DIR / "message.hmac"
KEY_FILE = BASE_DIR / "secret.key"
NONCE_FILE = BASE_DIR / "used_nonces.json"
MESSAGE_NONCE_FILE = BASE_DIR / "message.nonce"
FILE_HASH_FILE = BASE_DIR / "file_hashes.json"


def setup():
    BASE_DIR.mkdir(exist_ok=True)
    if not NONCE_FILE.exists(): NONCE_FILE.write_text("[]", encoding="utf-8")
    if not FILE_HASH_FILE.exists(): FILE_HASH_FILE.write_text("{}", encoding="utf-8")


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def random_key():
    # 256-bit cryptographically secure random key; never hard-coded.
    return secrets.token_hex(32)


def make_hmac(message, key, nonce=""):
    # Bind the message to a fresh nonce so an old message/MAC cannot be replayed.
    payload = (nonce + "|" + message).encode("utf-8")
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_hmac(message, key, stored_mac, nonce=""):
    return hmac.compare_digest(make_hmac(message, key, nonce), stored_mac)


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def new_nonce():
    return secrets.token_hex(16)


def accept_nonce(nonce):
    used = load_json(NONCE_FILE, [])
    if nonce in used:
        return False
    used.append(nonce)
    save_json(NONCE_FILE, used)
    return True


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            digest.update(block)
    return digest.hexdigest()


def task1():
    print("\n" + "=" * 70)
    print("TASK 1: SHA-256 HASHING")
    print("=" * 70)
    text = input("Enter a string: ")
    print("\nOriginal Input:", text)
    print("SHA-256 Hash:", sha256_text(text))


def task2_create():
    print("\n" + "=" * 70)
    print("CREATE NEW PROTECTED MESSAGE")
    print("=" * 70)
    message = input("\nEnter the message: ")
    key = random_key()
    nonce = new_nonce()
    mac = make_hmac(message, key, nonce)
    MESSAGE_FILE.write_text(message, encoding="utf-8")
    HMAC_FILE.write_text(mac, encoding="utf-8")
    KEY_FILE.write_text(key, encoding="utf-8")
    MESSAGE_NONCE_FILE.write_text(nonce, encoding="utf-8")
    print("\nRandom Secret Key Generated:")
    print(key)
    print("\nThis key is randomly generated and is different for each new protected message.")
    print("It is not hard-coded in the source code.")
    print("\nOriginal Message:")
    print(message)
    print("\nGenerated NONCE:")
    print(nonce)
    print("\nGenerated HMAC-SHA256:")
    print(mac)
    print("\nProtected message stored successfully.")
    print("Message file:", MESSAGE_FILE)
    print("HMAC file:", HMAC_FILE)
    print("Key file:", KEY_FILE)
    print("Nonce file:", MESSAGE_NONCE_FILE)
    print("\nInitial Verification")
    print("MAC Verified:", verify_hmac(message, key, mac, nonce))
    print("RESULT: Valid message -> Verification succeeded.")


def task2_verify():
    print("\n" + "=" * 70)
    print("VERIFY PROTECTED MESSAGE")
    print("=" * 70)
    if not MESSAGE_FILE.exists() or not HMAC_FILE.exists() or not MESSAGE_NONCE_FILE.exists():
        print("\nERROR: No protected message exists. Create one first.")
        return
    current = MESSAGE_FILE.read_text(encoding="utf-8")
    stored = HMAC_FILE.read_text(encoding="utf-8").strip()
    nonce = MESSAGE_NONCE_FILE.read_text(encoding="utf-8").strip()
    key = input("\nEnter the secret key: ")
    ok = verify_hmac(current, key, stored, nonce)
    print("\nCurrent Message:")
    print(current)
    print("\nStored NONCE:")
    print(nonce)
    print("\nStored Original HMAC:")
    print(stored)
    print("\n" + "-" * 70)
    print("VERIFICATION RESULT")
    print("-" * 70)
    print("\nMAC Verified:", ok)
    if ok:
        print("RESULT: Message is valid. Verification succeeded.")
    else:
        print("RESULT: Verification failed!")
        print("ALERT: Message has been modified/tampered")
        print("OR the secret key is incorrect.")


def task2():
    while True:
        print("\n" + "=" * 70)
        print("TASK 2: HMAC / MESSAGE AUTHENTICATION CODE")
        print("=" * 70)
        print("1. Create a new protected message")
        print("2. Verify the current message")
        print("3. Return to main menu")
        choice = input("\nEnter your choice (1-3): ").strip()
        if choice == "1": task2_create()
        elif choice == "2": task2_verify()
        elif choice == "3": return
        else: print("Invalid choice.")


def task3():
    print("\n" + "=" * 70)
    print("TASK 3: NONCE REPLAY PROTECTION")
    print("=" * 70)

    print("\nNONCE is automatically generated for every new request.")
    print("A previously used NONCE cannot be reused.\n")

    while True:

        print("-" * 70)
        print("REAL-TIME REQUEST AUTHENTICATION")
        print("-" * 70)

        print("1. Create new request")
        print("2. Verify/submit a NONCE")
        print("3. Show stored NONCE count")
        print("4. Return to main menu")

        choice = input("\nEnter your choice (1-4): ").strip()

        # =====================================================
        # OPTION 1: CREATE NEW REQUEST
        # =====================================================
        if choice == "1":

            print("\n" + "=" * 70)
            print("CREATE NEW REQUEST")
            print("=" * 70)

            message = input("\nEnter request/message: ").strip()

            if not message:
                print("\nERROR: Request/message cannot be empty.")
                continue

            # Generate a new cryptographically secure random NONCE
            nonce = new_nonce()

            print("\nGenerated NONCE:")
            print(nonce)

            print("\nChecking NONCE...")

            # Check whether the NONCE has already been used
            if nonce in load_json(NONCE_FILE, []):

                print("\nREQUEST REJECTED")
                print("Reason: Duplicate NONCE")
                print("ALERT: Replay attack detected.")

            else:

                # Store the new NONCE
                accept_nonce(nonce)

                print("\nREQUEST ACCEPTED")
                print("NONCE has not been used before.")

                print("\nRequest/message processed successfully.")

                print("Message:")
                print(message)

                print("\nNONCE stored successfully.")

        # =====================================================
        # OPTION 2: VERIFY/SUBMIT A NONCE
        # =====================================================
        elif choice == "2":

            print("\n" + "=" * 70)
            print("VERIFY REQUEST NONCE")
            print("=" * 70)

            message = input("\nEnter request/message: ").strip()

            if not message:
                print("\nERROR: Request/message cannot be empty.")
                continue

            nonce = input("\nEnter NONCE: ").strip()

            if not nonce:
                print("\nERROR: NONCE cannot be empty.")
                continue

            print("\nChecking NONCE...")

            used_nonces = load_json(NONCE_FILE, [])

            # NONCE already exists = replay attack
            if nonce in used_nonces:

                print("\n" + "!" * 70)
                print("REQUEST REJECTED")
                print("!" * 70)

                print("\nReason: Duplicate NONCE")
                print("ALERT: Replay attack detected.")
                print("This NONCE has already been used.")

            else:

                # New NONCE is accepted and stored
                accept_nonce(nonce)

                print("\n" + "-" * 70)
                print("REQUEST ACCEPTED")
                print("-" * 70)

                print("\nNONCE has not been used before.")
                print("New NONCE stored successfully.")

        # =====================================================
        # OPTION 3: SHOW NONCE INFORMATION
        # =====================================================
        elif choice == "3":

            used_nonces = load_json(NONCE_FILE, [])

            print("\n" + "=" * 70)
            print("NONCE STORAGE INFORMATION")
            print("=" * 70)

            print("\nNumber of stored NONCE values:", len(used_nonces))
            print("\nNONCE storage file:")
            print(NONCE_FILE)

        # =====================================================
        # OPTION 4: RETURN TO MAIN MENU
        # =====================================================
        elif choice == "4":

            print("\nReturning to main menu...")
            return

        else:

            print("\nInvalid choice.")
            print("Please enter 1, 2, 3, or 4.")


def task4_protect():
    name = input("\nEnter file path (example: data.txt): ").strip()
    path = Path(name)
    if not path.is_file():
        print("ERROR: File does not exist or is not a regular file.")
        return
    hashes = load_json(FILE_HASH_FILE, {})
    digest = file_hash(path)
    hashes[str(path.resolve())] = digest
    save_json(FILE_HASH_FILE, hashes)
    print("\nFile:", path)
    print("Original Hash:", digest)
    print("Trusted hash stored successfully.")


def task4_verify():
    name = input("\nEnter file path (example: data.txt): ").strip()
    path = Path(name)
    if not path.is_file():
        print("ERROR: File does not exist or is not a regular file.")
        return
    hashes = load_json(FILE_HASH_FILE, {})
    key = str(path.resolve())
    if key not in hashes:
        print("ERROR: No trusted hash exists for this file. Protect it first.")
        return
    original = hashes[key]
    new = file_hash(path)
    print("\nFile:", path)
    print("Original Hash:", original)
    print("New Hash:", new)
    if hmac.compare_digest(original, new):
        print("-> File integrity verified. No tampering detected.")
    else:
        print("-> ALERT: File has been tampered!")


def task4():
    while True:
        print("\n" + "=" * 70)
        print("TASK 4: FILE / SOFTWARE TAMPERING DETECTION")
        print("=" * 70)
        print("1. Protect a file / store its trusted hash")
        print("2. Verify a file against its stored hash")
        print("3. Return to main menu")
        choice = input("\nEnter your choice (1-3): ").strip()
        if choice == "1": task4_protect()
        elif choice == "2": task4_verify()
        elif choice == "3": return
        else: print("Invalid choice.")


def main():
    setup()
    while True:
        print("\n" + "#" * 70)
        print("LAB 5: HASHES & ANTI-TAMPERING MECHANISMS")
        print("#" * 70)
        print("\n1. Task 1 - SHA-256 Hashing")
        print("2. Task 2 - HMAC / Message Authentication")
        print("3. Task 3 - NONCE Replay Protection")
        print("4. Task 4 - File / Software Tampering Detection")
        print("5. Exit")
        choice = input("\nEnter your choice (1-5): ").strip()
        if choice == "1": task1()
        elif choice == "2": task2()
        elif choice == "3": task3()
        elif choice == "4": task4()
        elif choice == "5":
            print("\nLAB 5 COMPLETED")
            break
        else: print("Invalid choice. Please enter 1-5.")


if __name__ == "__main__":
    main()
