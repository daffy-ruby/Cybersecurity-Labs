from pathlib import Path
import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_DIR = Path("hospital_keys")
KEY_DIR.mkdir(exist_ok=True)

A_PUBLIC_FILE = KEY_DIR / "hospital_A_public.pem"
B_PUBLIC_FILE = KEY_DIR / "hospital_B_public.pem"

# RSA keys stay in application memory
endpoint_a_private_key = None
endpoint_a_public_key = None
endpoint_b_private_key = None
endpoint_b_public_key = None

# Exchanged public keys
received_a_public_key = None
received_b_public_key = None

# DH state
dh_parameters = None
dh_a_private_key = None
dh_a_public_key = None
dh_b_private_key = None
dh_b_public_key = None
dh_shared_secret_a = None
dh_shared_secret_b = None

# AES state
aes_session_key = None
aes_nonce = None
aes_ciphertext = None
encrypted_session_key = None


def pause():
    input("\nPress ENTER to continue...")


def line(char="=", length=78):
    print(char * length)


def fingerprint(public_key):
    data = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(data).hexdigest()


def generate_endpoint_keys(name):
    print(f"\nGenerating RSA-3072 key pair for {name}...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )
    public_key = private_key.public_key()

    print(f"{name} RSA key pair generated successfully.")
    print("Private key: stored securely in application memory.")
    print("Public key: available for secure communication.")
    return private_key, public_key


def export_public_key(public_key, filename):
    data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as f:
        f.write(data)


def import_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def exchange_public_keys():
    global received_a_public_key, received_b_public_key

    if endpoint_a_public_key is None or endpoint_b_public_key is None:
        print("\nERROR: Generate RSA keys first.")
        return False

    print("\n" + "-" * 78)
    print("PUBLIC KEY EXPORT AND EXCHANGE")
    print("-" * 78)

    export_public_key(endpoint_a_public_key, A_PUBLIC_FILE)
    export_public_key(endpoint_b_public_key, B_PUBLIC_FILE)

    print("\nHospital A public key exported:")
    print(A_PUBLIC_FILE)

    print("\nHospital B public key exported:")
    print(B_PUBLIC_FILE)

    # Hospital A -> Hospital B
    received_a_public_key = import_public_key(A_PUBLIC_FILE)

    # Hospital B -> Hospital A
    received_b_public_key = import_public_key(B_PUBLIC_FILE)

    a_local = fingerprint(endpoint_a_public_key)
    a_received = fingerprint(received_a_public_key)
    b_local = fingerprint(endpoint_b_public_key)
    b_received = fingerprint(received_b_public_key)

    print("\nHospital A -> Hospital B: PUBLIC KEY RECEIVED")
    print("Hospital A fingerprint :", a_local)
    print("Hospital B received FP :", a_received)

    print("\nHospital B -> Hospital A: PUBLIC KEY RECEIVED")
    print("Hospital B fingerprint :", b_local)
    print("Hospital A received FP :", b_received)

    a_ok = a_local == a_received
    b_ok = b_local == b_received

    print("\nHospital A public-key verification:",
          "VALID" if a_ok else "FAILED")
    print("Hospital B public-key verification:",
          "VALID" if b_ok else "FAILED")

    if a_ok and b_ok:
        print("\nRESULT: PUBLIC KEYS EXCHANGED SUCCESSFULLY.")
        print("Private keys were NOT exported or exchanged.")
        return True

    print("\nRESULT: PUBLIC KEY EXCHANGE VERIFICATION FAILED.")
    return False


def live_security_setup():
    global endpoint_a_private_key, endpoint_a_public_key
    global endpoint_b_private_key, endpoint_b_public_key

    line()
    print("LIVE SECURITY SETUP / KEY GENERATION")
    line()

    choice = input(
        "\nGenerate fresh RSA-3072 key pairs for Hospital A and B? (y/n): "
    ).strip().lower()

    if choice != "y":
        print("Key generation cancelled.")
        pause()
        return

    endpoint_a_private_key, endpoint_a_public_key =         generate_endpoint_keys("Hospital A")

    endpoint_b_private_key, endpoint_b_public_key =         generate_endpoint_keys("Hospital B")

    print("\nHospital A Public-Key Fingerprint:")
    print(fingerprint(endpoint_a_public_key))

    print("\nHospital B Public-Key Fingerprint:")
    print(fingerprint(endpoint_b_public_key))

    exchange_public_keys()

    print("\n" + "-" * 78)
    print("SECURITY RESULT")
    print("-" * 78)
    print("RSA-3072 key pairs: GENERATED")
    print("Public keys: EXPORTED")
    print("Public keys: EXCHANGED")
    print("Public keys: FINGERPRINT VERIFIED")
    print("Private keys: NOT EXPORTED")
    print("Private keys: CONFIDENTIAL IN APPLICATION MEMORY")

    pause()


def keys_ready():
    if endpoint_a_private_key is None or endpoint_b_private_key is None:
        print("\nERROR: RSA keys are not generated.")
        print("Select option 1 first.")
        return False

    if received_a_public_key is None or received_b_public_key is None:
        print("\nERROR: Public keys have not been exchanged.")
        print("Select option 1 first.")
        return False

    return True


def rsa_encrypt_decrypt():
    if not keys_ready():
        pause()
        return

    line()
    print("RSA PATIENT MESSAGE ENCRYPTION & DECRYPTION")
    line()

    sender = input("\nEnter sender endpoint (A/B): ").strip().upper()
    if sender not in ("A", "B"):
        print("Invalid endpoint.")
        pause()
        return

    message = input("Enter patient message / medical record: ")

    if sender == "A":
        recipient_public = received_b_public_key
        recipient_private = endpoint_b_private_key
        recipient = "Hospital B"
    else:
        recipient_public = received_a_public_key
        recipient_private = endpoint_a_private_key
        recipient = "Hospital A"

    ciphertext = recipient_public.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"\nEncrypting for {recipient} using RSA-OAEP...")
    print("\nCiphertext (Base64):")
    print(base64.b64encode(ciphertext).decode())

    plaintext = recipient_private.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

    print("\nDecrypted message:")
    print(plaintext)
    print("\nRESULT:", "SUCCESS" if plaintext == message else "FAILED")
    pause()


def signature_and_tamper():
    if not keys_ready():
        pause()
        return

    line()
    print("DIGITAL SIGNATURE & REAL-TIME TAMPER DETECTION")
    line()

    sender = input("\nEnter sender endpoint (A/B): ").strip().upper()
    if sender not in ("A", "B"):
        print("Invalid endpoint.")
        pause()
        return

    message = input("Enter message/medical record to digitally sign: ")

    if sender == "A":
        private_key = endpoint_a_private_key
        public_key = received_a_public_key
    else:
        private_key = endpoint_b_private_key
        public_key = received_b_public_key

    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("\nORIGINAL MESSAGE")
    print("-" * 78)
    print(message)

    print("\nDigital Signature (Base64):")
    print(base64.b64encode(signature).decode())

    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\nOriginal verification: VALID")
    except Exception:
        print("\nOriginal verification: INVALID")
        pause()
        return

    print("\nREAL-TIME TAMPER TEST")
    print("-" * 78)
    print("Press ENTER to keep the original message.")
    received = input("Enter received/modified message: ")

    if received == "":
        received = message

    try:
        public_key.verify(
            signature,
            received.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\n" + "=" * 78)
        print("RESULT: SIGNATURE VALID")
        print("=" * 78)
        print("Message accepted.")
        print("No modification detected.")
    except Exception:
        print("\n" + "=" * 78)
        print("RESULT: TAMPERING DETECTED")
        print("=" * 78)
        print("Signature verification failed.")
        print("The received message was modified or is not authentic.")

    pause()


def rsa_session_aes():
    global aes_session_key, aes_nonce
    global aes_ciphertext, encrypted_session_key

    if not keys_ready():
        pause()
        return

    line()
    print("RSA SESSION-KEY EXCHANGE + AES-256-GCM")
    line()

    sender = input("\nEnter sender hospital (A/B): ").strip().upper()
    if sender not in ("A", "B"):
        print("Invalid endpoint.")
        pause()
        return

    message = input("Enter patient record/message: ")

    if sender == "A":
        recipient_public = received_b_public_key
        recipient_private = endpoint_b_private_key
        recipient = "Hospital B"
    else:
        recipient_public = received_a_public_key
        recipient_private = endpoint_a_private_key
        recipient = "Hospital A"

    aes_session_key = AESGCM.generate_key(bit_length=256)
    aes_nonce = os.urandom(12)

    aes = AESGCM(aes_session_key)
    aes_ciphertext = aes.encrypt(
        aes_nonce,
        message.encode(),
        None
    )

    encrypted_session_key = recipient_public.encrypt(
        aes_session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\nAES-256 session key generated.")
    print("Patient data encrypted with AES-256-GCM.")
    print(f"AES session key protected with {recipient} RSA public key.")

    print("\nEncrypted AES session key (Base64):")
    print(base64.b64encode(encrypted_session_key).decode())

    print("\nAES nonce (Base64):")
    print(base64.b64encode(aes_nonce).decode())

    print("\nAES-GCM ciphertext (Base64):")
    print(base64.b64encode(aes_ciphertext).decode())

    recovered_key = recipient_private.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    recovered_message = AESGCM(recovered_key).decrypt(
        aes_nonce,
        aes_ciphertext,
        None
    ).decode()

    print("\nRecipient decrypted message:")
    print(recovered_message)
    print("\nRESULT:",
          "HYBRID ENCRYPTION SUCCESSFUL"
          if recovered_message == message else "FAILED")

    pause()


def diffie_hellman_exchange():
    global dh_parameters, dh_a_private_key, dh_a_public_key
    global dh_b_private_key, dh_b_public_key
    global dh_shared_secret_a, dh_shared_secret_b

    line()
    print("DIFFIE-HELLMAN KEY EXCHANGE")
    line()

    print("\nGenerating DH parameters...")
    dh_parameters = dh.generate_parameters(
        generator=2,
        key_size=2048
    )

    dh_a_private_key = dh_parameters.generate_private_key()
    dh_a_public_key = dh_a_private_key.public_key()

    dh_b_private_key = dh_parameters.generate_private_key()
    dh_b_public_key = dh_b_private_key.public_key()

    dh_shared_secret_a = dh_a_private_key.exchange(dh_b_public_key)
    dh_shared_secret_b = dh_b_private_key.exchange(dh_a_public_key)

    hash_a = hashlib.sha256(dh_shared_secret_a).hexdigest()
    hash_b = hashlib.sha256(dh_shared_secret_b).hexdigest()

    print("\nHospital A shared-secret SHA-256:")
    print(hash_a)

    print("\nHospital B shared-secret SHA-256:")
    print(hash_b)

    if dh_shared_secret_a == dh_shared_secret_b:
        print("\nRESULT: DIFFIE-HELLMAN EXCHANGE SUCCESSFUL")
        print("Both hospitals calculated the same shared secret.")
    else:
        print("\nRESULT: DIFFIE-HELLMAN EXCHANGE FAILED")

    pause()


def show_key_status():
    line()
    print("LIVE KEY STATUS")
    line()

    if endpoint_a_private_key is not None:
        print("Endpoint A RSA: GENERATED")
        print("  Algorithm : RSA-3072")
        print("  Private Key: AVAILABLE IN MEMORY")
        print("  Public Key : AVAILABLE")
        print("  Public Key File:", A_PUBLIC_FILE)
    else:
        print("Endpoint A RSA: NOT GENERATED")

    print()

    if endpoint_b_private_key is not None:
        print("Endpoint B RSA: GENERATED")
        print("  Algorithm : RSA-3072")
        print("  Private Key: AVAILABLE IN MEMORY")
        print("  Public Key : AVAILABLE")
        print("  Public Key File:", B_PUBLIC_FILE)
    else:
        print("Endpoint B RSA: NOT GENERATED")

    print()

    print(
        "Public-Key Exchange:",
        "COMPLETED"
        if received_a_public_key is not None and received_b_public_key is not None
        else "NOT COMPLETED"
    )

    print(
        "Diffie-Hellman:",
        "GENERATED"
        if dh_shared_secret_a is not None else "NOT GENERATED"
    )

    print(
        "AES-256 Session Key:",
        "GENERATED"
        if aes_session_key is not None else "NOT GENERATED"
    )

    print(
        "RSA Encrypted Session Key:",
        "GENERATED"
        if encrypted_session_key is not None else "NOT GENERATED"
    )

    pause()


def run_all():
    global endpoint_a_private_key, endpoint_a_public_key
    global endpoint_b_private_key, endpoint_b_public_key
    global dh_parameters, dh_a_private_key, dh_a_public_key
    global dh_b_private_key, dh_b_public_key
    global dh_shared_secret_a, dh_shared_secret_b

    line("#")
    print("COMPLETE SECURE COMMUNICATION DEMONSTRATION")
    line("#")

    print("\n[1] RSA-3072 key generation")
    endpoint_a_private_key, endpoint_a_public_key =         generate_endpoint_keys("Hospital A")
    endpoint_b_private_key, endpoint_b_public_key =         generate_endpoint_keys("Hospital B")

    print("\n[2] Public-key export and exchange")
    if not exchange_public_keys():
        pause()
        return

    message = "Patient123 Medication Insulin"

    print("\n[3] RSA-OAEP encryption/decryption")
    ciphertext = received_b_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted = endpoint_b_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    print("Original :", message)
    print("Decrypted:", decrypted)
    print("Result   :", "VALID" if message == decrypted else "FAILED")

    print("\n[4] RSA-PSS signature and tamper detection")
    signature = endpoint_a_private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    try:
        received_a_public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Original verification: VALID")
    except Exception:
        print("Original verification: FAILED")

    tampered = "Patient123 Medication Changed"
    try:
        received_a_public_key.verify(
            signature,
            tampered.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Tampered verification: INCORRECTLY VALID")
    except Exception:
        print("Tampered verification: TAMPERING DETECTED")

    print("\n[5] RSA-protected AES-256-GCM")
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(
        nonce, message.encode(), None
    )
    encrypted_key = received_b_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    recovered_key = endpoint_b_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    recovered = AESGCM(recovered_key).decrypt(
        nonce, ciphertext, None
    ).decode()
    print("Recovered:", recovered)
    print("Result   :", "VALID" if recovered == message else "FAILED")

    print("\n[6] Diffie-Hellman exchange")
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
    dh_a_private_key = dh_parameters.generate_private_key()
    dh_a_public_key = dh_a_private_key.public_key()
    dh_b_private_key = dh_parameters.generate_private_key()
    dh_b_public_key = dh_b_private_key.public_key()

    dh_shared_secret_a = dh_a_private_key.exchange(dh_b_public_key)
    dh_shared_secret_b = dh_b_private_key.exchange(dh_a_public_key)

    print(
        "DH shared secret match:",
        "VALID" if dh_shared_secret_a == dh_shared_secret_b else "FAILED"
    )

    line("#")
    print("COMPLETE DEMONSTRATION FINISHED")
    line("#")
    print("\nPrivate keys were never exported or exchanged.")
    pause()


def main():
    while True:
        print("\n")
        line("#")
        print("LAB 6 - REAL-TIME SECURE COMMUNICATION APPLICATION")
        line("#")
        print("1. Live Security Setup / Key Generation + Public-Key Exchange")
        print("2. RSA Patient Message Encryption & Decryption")
        print("3. Digital Signature & Tamper Detection")
        print("4. RSA Session-Key Exchange + AES-256-GCM")
        print("5. Diffie-Hellman Key Exchange")
        print("6. Show Live Key Status")
        print("7. Run All Interactively")
        print("8. Exit")
        line()

        choice = input("Enter your choice (1-8): ").strip()

        if choice == "1":
            live_security_setup()
        elif choice == "2":
            rsa_encrypt_decrypt()
        elif choice == "3":
            signature_and_tamper()
        elif choice == "4":
            rsa_session_aes()
        elif choice == "5":
            diffie_hellman_exchange()
        elif choice == "6":
            show_key_status()
        elif choice == "7":
            run_all()
        elif choice == "8":
            print("\nExiting application...")
            break
        else:
            print("\nInvalid choice. Enter a number from 1 to 8.")


if __name__ == "__main__":
    main()
