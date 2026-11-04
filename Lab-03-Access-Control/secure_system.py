import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from getpass import getpass

BASE = Path(__file__).resolve().parent
DATA = BASE / "secure_storage"
PRESCRIPTIONS = DATA / "prescriptions"
USERS_FILE = BASE / "users.json"
RECORDS_FILE = BASE / "patient_records.json"
META_FILE = BASE / "metadata.json"
AUDIT_LOG = BASE / "audit.log"
SMS_LOG = BASE / "sms_notifications.log"

DATA.mkdir(exist_ok=True)
PRESCRIPTIONS.mkdir(exist_ok=True)

ITERATIONS = 310_000

# ---------------- Logging ----------------
logger = logging.getLogger("Lab3")
logger.setLevel(logging.INFO)
logger.handlers.clear()
handler = logging.FileHandler(AUDIT_LOG, encoding="utf-8")
handler.setFormatter(logging.Formatter(
    "[%(asctime)s] User: %(user)s | Action: %(action)s | "
    "Target: %(target)s | Result: %(result)s | %(message)s"
))
logger.addHandler(handler)

class AuditFilter(logging.Filter):
    def filter(self, record):
        record.user = getattr(record, "user", "SYSTEM")
        record.action = getattr(record, "action", "SYSTEM")
        record.target = getattr(record, "target", "-")
        record.result = getattr(record, "result", "INFO")
        return True

handler.addFilter(AuditFilter())

def audit(user, action, target, result, message):
    logger.info(message, extra={
        "user": user, "action": action,
        "target": target, "result": result
    })

# ---------------- Helpers ----------------
def load_json(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def save_json(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)

def password_hash(password, salt=None):
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, ITERATIONS
    )
    return salt.hex(), digest.hex()

def verify_password(password, salt_hex, expected):
    try:
        salt = bytes.fromhex(salt_hex)
        _, actual = password_hash(password, salt)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def valid_email(email):
    return bool(re.fullmatch(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        email.strip()
    ))

def valid_mobile(mobile):
    return bool(re.fullmatch(r"\+?[0-9][0-9 ()-]{7,18}", mobile.strip()))

# ---------------- Secure Healthcare System ----------------
class HealthcareSystem:
    def __init__(self):
        self.users = load_json(USERS_FILE, {})
        self.records = load_json(RECORDS_FILE, {})
        self.metadata = load_json(META_FILE, {})
        self.failed = {}
        self.locked = set()

    # ----- Accounts -----
    def create_account(self, email, password, role, mobile=""):
        email = email.strip().lower()
        role = role.strip().title()
        if role not in {"Admin", "Doctor", "Nurse", "Patient"}:
            raise ValueError("Role must be Admin, Doctor, Nurse, or Patient.")
        if not valid_email(email):
            raise ValueError("Invalid email address.")
        if email in self.users:
            raise ValueError("Account already exists.")
        if mobile and not valid_mobile(mobile):
            raise ValueError("Invalid mobile number.")

        salt, digest = password_hash(password)
        self.users[email] = {
            "role": role,
            "mobile": mobile,
            "salt": salt,
            "password_hash": digest,
            "created_at": datetime.now().isoformat(timespec="seconds")
        }
        save_json(USERS_FILE, self.users)
        audit(email, "CREATE_ACCOUNT", email, "SUCCESS", f"{role} account created")
        print(f"ACCOUNT CREATED: {email} ({role})")

    def login(self, email, password):
        email = email.strip().lower()
        if email in self.locked:
            raise PermissionError("Account is locked after 3 failed attempts.")

        account = self.users.get(email)
        if not account or not verify_password(
            password, account["salt"], account["password_hash"]
        ):
            self.failed[email] = self.failed.get(email, 0) + 1
            audit(email, "LOGIN", email, "FAILURE",
                  f"Invalid credentials; attempt {self.failed[email]}")
            if self.failed[email] >= 3:
                self.locked.add(email)
                audit(email, "LOCK_ACCOUNT", email, "FAILURE",
                      "Account locked after 3 failed attempts")
                raise PermissionError("Account locked after 3 failed attempts.")
            raise PermissionError(f"Invalid credentials ({self.failed[email]}/3).")

        self.failed[email] = 0
        role = account["role"]
        audit(email, "LOGIN", email, "SUCCESS", f"Authenticated as {role}")
        print(f"LOGIN SUCCESS: {email} ({role})")
        return {"email": email, "role": role, "mobile": account.get("mobile", "")}

    def require(self, user, roles):
        if user["role"] not in roles:
            audit(user["email"], "AUTHORIZATION", "-", "FAILURE",
                  f"Role {user['role']} denied; required {roles}")
            raise PermissionError("Insufficient permission.")

    # ----- Patient records -----
    def create_record(self, user, patient_email, name, mobile, history, current):
        self.require(user, {"Admin"})
        patient_email = patient_email.strip().lower()
        if patient_email not in self.users or self.users[patient_email]["role"] != "Patient":
            raise ValueError("Patient account does not exist.")
        if not valid_mobile(mobile):
            raise ValueError("Invalid mobile number.")

        self.records[patient_email] = {
            "patient_name": name,
            "patient_email": patient_email,
            "mobile": mobile,
            "previous_history": history,
            "current_record": current,
            "next_visit": None,
            "updated_at": datetime.now().isoformat(timespec="seconds")
        }
        self.users[patient_email]["mobile"] = mobile
        save_json(RECORDS_FILE, self.records)
        save_json(USERS_FILE, self.users)
        audit(user["email"], "CREATE_RECORD", patient_email, "SUCCESS",
              "Patient record created")
        print("ACCESS GRANTED: Patient record created.")

    def update_visit(self, user, patient_email, date, time, department):
        self.require(user, {"Admin"})
        patient_email = patient_email.strip().lower()
        if patient_email not in self.records:
            raise FileNotFoundError("Patient record does not exist.")

        self.records[patient_email]["next_visit"] = {
            "date": date,
            "time": time,
            "department": department
        }
        save_json(RECORDS_FILE, self.records)

        mobile = self.records[patient_email]["mobile"]
        message = (
            f"Next visit: {date} at {time}, {department}"
        )
        with SMS_LOG.open("a", encoding="utf-8") as f:
            f.write(
                f"[{datetime.now().isoformat(timespec='seconds')}] "
                f"SMS QUEUED -> {mobile} | {message}\n"
            )

        audit(user["email"], "UPDATE_NEXT_VISIT", patient_email, "SUCCESS",
              f"Visit {date} {time}; mobile notification queued")
        print("NEXT VISIT UPDATED SUCCESSFULLY.")
        print(f"Date: {date}")
        print(f"Time: {time}")
        print(f"Department: {department}")
        print(f"Mobile notification queued for: {mobile}")

    def view_record(self, user, patient_email):
        patient_email = patient_email.strip().lower()
        if user["role"] == "Patient" and user["email"] != patient_email:
            raise PermissionError("Patients can view only their own record.")
        record = self.records.get(patient_email)
        if not record:
            raise FileNotFoundError("No patient record found.")
        audit(user["email"], "READ_RECORD", patient_email, "SUCCESS",
              "Patient record viewed")
        print("\n===== PATIENT RECORD =====")
        for key, value in record.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
        print("==========================")

    # ----- Prescription -----
    def prescription_path(self, patient_email):
        safe = re.sub(r"[^A-Za-z0-9._@-]", "_", patient_email.lower())
        return PRESCRIPTIONS / f"{safe}.txt"

    def write_prescription(self, user, patient_email, medicine, dosage,
                           duration, instructions):
        self.require(user, {"Doctor", "Admin"})
        patient_email = patient_email.strip().lower()
        record = self.records.get(patient_email)
        if not record:
            raise FileNotFoundError("Patient record does not exist.")

        content = f"""===== PRESCRIPTION =====
Doctor Name: {user['email']}
Patient Name: {record['patient_name']}
Patient Email: {patient_email}
Patient Mobile: {record['mobile']}
Previous Medical History: {record['previous_history']}
Current Patient Record: {record['current_record']}
Medicine: {medicine}
Dosage: {dosage}
Duration: {duration}
Instructions: {instructions}
Next Visit: {record['next_visit']}
========================
"""
        path = self.prescription_path(patient_email)
        path.write_text(content, encoding="utf-8")
        self.metadata[patient_email] = {
            "sha256": file_hash(path),
            "permissions": {
                "Admin": "rw",
                "Doctor": "rw",
                "Nurse": "r",
                "Patient": "r-own"
            },
            "doctor": user["email"],
            "modified_at": datetime.now().isoformat(timespec="seconds")
        }
        save_json(META_FILE, self.metadata)
        audit(user["email"], "PRESCRIPTION_WRITE", patient_email, "SUCCESS",
              "Prescription created/updated")
        print("ACCESS GRANTED: Prescription written successfully.")
    def update_prescription_field(self, user, patient_email, field, new_value):
        patient_email = patient_email.strip().lower()

        # Only Doctor and Admin can modify prescriptions.
        if user["role"] not in {"Doctor", "Admin"}:
            audit(
                user["email"],
                "PRESCRIPTION_UPDATE",
                patient_email,
                "FAILURE",
                f"{user['role']} attempted to change {field}"
            )

            print("\nACCESS DENIED")
            print(
                f"{user['role']} does not have permission to modify "
                "prescriptions."
            )
            print("Prescription was NOT changed.")
            return

        path = self.prescription_path(patient_email)

        if not path.exists():
            raise FileNotFoundError("Prescription does not exist.")

        content = path.read_text(encoding="utf-8")

        field_labels = {
            "medicine": "Medicine",
            "dosage": "Dosage"
        }

        label = field_labels.get(field)

        if not label:
            raise ValueError("Invalid prescription field.")

        lines = content.splitlines()
        updated = False

        for i, line in enumerate(lines):
            if line.startswith(f"{label}:"):
                lines[i] = f"{label}: {new_value}"
                updated = True
                break

        if not updated:
            raise ValueError(f"{label} field not found.")

        path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8"
        )

        # Recalculate SHA-256 after an authorized change.
        self.metadata[patient_email]["sha256"] = file_hash(path)
        self.metadata[patient_email]["modified_at"] = (
            datetime.now().isoformat(timespec="seconds")
        )

        save_json(META_FILE, self.metadata)

        audit(
            user["email"],
            "PRESCRIPTION_UPDATE",
            patient_email,
            "SUCCESS",
            f"{label} updated successfully"
        )

        print("ACCESS GRANTED")
        print(f"{label} updated successfully.")

    def read_prescription(self, user, patient_email):
        patient_email = patient_email.strip().lower()

        if user["role"] == "Patient" and user["email"] != patient_email:
            audit(user["email"], "PRESCRIPTION_READ", patient_email, "FAILURE",
                  "Patient attempted another patient's prescription")
            raise PermissionError("Patients can view only their own prescription.")

        if user["role"] not in {"Admin", "Doctor", "Nurse", "Patient"}:
            raise PermissionError("Insufficient permission.")

        path = self.prescription_path(patient_email)
        if not path.exists():
            raise FileNotFoundError("Prescription does not exist.")

        stored = self.metadata.get(patient_email, {}).get("sha256")
        current = file_hash(path)
        if not stored or stored != current:
            audit(user["email"], "INTEGRITY_CHECK", patient_email, "FAILURE",
                  "SHA-256 hash mismatch; tampering detected")
            print("ALERT: Prescription integrity violation detected!")
            print("SHA-256 hash mismatch.")
            raise RuntimeError("Integrity verification failed.")

        content = path.read_text(encoding="utf-8")
        audit(user["email"], "PRESCRIPTION_READ", patient_email, "SUCCESS",
              f"{user['role']} viewed prescription")
        print("ACCESS GRANTED: Prescription read.")
        print(content)
        return content

    def secure_delete_file(self, user, file_name):
        """Securely delete a file after authorization."""

        # Only Admin can delete files
        self.require(user, {"Admin"})

        # This lab stores prescription files here
        path = PRESCRIPTIONS / file_name

        if not path.exists():
            audit(
                user["email"],
                "DELETE",
                file_name,
                "FAILURE",
                "File not found"
            )
            print("ERROR: File does not exist.")
            return

        try:
            # Overwrite file contents before deletion
            file_size = path.stat().st_size

            if file_size > 0:
                with open(path, "r+b") as f:
                    f.write(b"\x00" * file_size)
                    f.flush()
                    os.fsync(f.fileno())

            # Delete the file
            path.unlink()

            # Remove corresponding SHA-256 metadata
            patient_email = Path(file_name).stem
            self.metadata.pop(patient_email, None)
            save_json(META_FILE, self.metadata)

            audit(
                user["email"],
                "DELETE",
                file_name,
                "SUCCESS",
                "File securely deleted"
            )

            print("SECURE DELETE: File deleted successfully.")

        except Exception as e:
            audit(
                user["email"],
                "DELETE",
                file_name,
                "FAILURE",
                f"Secure deletion failed: {e}"
            )
            print(f"ERROR: Secure deletion failed: {e}")
    # ----- Demonstration -----
    def security_demo(self):
        print("\n=== SECURITY DEMONSTRATION ===")
        print("This demonstration uses your existing accounts and patient record.")
        print("No demo patient or demo accounts will be created.\n")

        # Login using accounts already created by the user
        print("Enter the existing Admin account")
        admin_email = input("Admin email: ").strip().lower()
        admin_password = getpass("Admin password: ")

        print("\nEnter the existing Doctor account")
        doctor_email = input("Doctor email: ").strip().lower()
        doctor_password = getpass("Doctor password: ")

        print("\nEnter the existing Nurse account")
        nurse_email = input("Nurse email: ").strip().lower()
        nurse_password = getpass("Nurse password: ")

        print("\nEnter the existing Patient account")
        patient_email = input("Patient email: ").strip().lower()
        patient_password = getpass("Patient password: ")

        try:
            admin = self.login(admin_email, admin_password)
            doctor = self.login(doctor_email, doctor_password)
            nurse = self.login(nurse_email, nurse_password)
            patient = self.login(patient_email, patient_password)
        except PermissionError as e:
            print(f"LOGIN ERROR: {e}")
            return

        # Check that patient record exists
        if patient_email not in self.records:
            print("ERROR: Patient record does not exist.")
            print("Create the patient's record through the Admin account first.")
            return

        print("\n[1] PATIENT RECORD")
        self.view_record(admin, patient_email)

        print("\n[2] DOCTOR CREATES/UPDATES PRESCRIPTION")

        self.write_prescription(
            doctor,
            patient_email,
            input("Medicine: "),
            input("Dosage: "),
            input("Duration: "),
            input("Instructions: ")
        )

        print("\n[3] NURSE READS PRESCRIPTION")
        self.read_prescription(nurse, patient_email)

        print("\n[4] NURSE ATTEMPTS TO MODIFY PRESCRIPTION")
        self.update_prescription_field(
            nurse,
            patient_email,
            "medicine",
            "Unauthorized Medicine"
)

        print("\n[5] PATIENT VIEWS OWN PRESCRIPTION")
        self.read_prescription(patient, patient_email)

        print("\n[6] PATIENT CHECKS NEXT VISIT")
        self.view_record(patient, patient_email)

        print("\n[7] SIMULATE UNAUTHORIZED TAMPERING")

        path = self.prescription_path(patient_email)

        with path.open("a", encoding="utf-8") as f:
            f.write("\nUNAUTHORIZED MODIFICATION")

        print("Unauthorized modification inserted into YOUR patient's prescription file.")

        print("\n[8] NURSE READS TAMPERED PRESCRIPTION")

        try:
            self.read_prescription(nurse, patient_email)
        except RuntimeError:
            pass

        print("\n=== DEMONSTRATION COMPLETE ===")
        print(f"Audit log: {AUDIT_LOG}")
        print(f"SHA-256 metadata: {META_FILE}")
        print(f"SMS queue: {SMS_LOG}")
# ---------------- Menus ----------------
def create_account_menu(system):
    print("\n=== CREATE ACCOUNT ===")
    print("1. Admin")
    print("2. Doctor")
    print("3. Nurse")
    print("4. Patient")
    choice = input("Choose: ").strip()
    role = {"1":"Admin", "2":"Doctor", "3":"Nurse", "4":"Patient"}.get(choice)
    if not role:
        print("Invalid option.")
        return
    email = input("Email (username): ").strip()
    password = getpass("Password: ")
    mobile = input("Mobile number: ").strip()
    try:
        system.create_account(email, password, role, mobile)
    except ValueError as e:
        print(f"ERROR: {e}")

def admin_menu(system, user):
    while True:
        print("\n=== ADMIN MENU ===")
        print("1. Create patient record")
        print("2. Update next visit")
        print("3. View patient record")
        print("4. Write/update prescription")
        print("5. Securely delete prescription")
        print("6. Logout")

        c = input("Choose: ").strip()

        try:
            if c == "1":
                p = input("Patient email: ")
                system.create_record(
                    user,
                    p,
                    input("Patient name: "),
                    input("Mobile: "),
                    input("Previous history: "),
                    input("Current record: ")
                )

            elif c == "2":
                system.update_visit(
                    user,
                    input("Patient email: "),
                    input("Visit date: "),
                    input("Visit time: "),
                    input("Department: ")
                )

            elif c == "3":
                system.view_record(
                    user,
                    input("Patient email: ")
                )

            elif c == "4":
                p = input("Patient email: ")
                system.write_prescription(
                    user,
                    p,
                    input("Medicine: "),
                    input("Dosage: "),
                    input("Duration: "),
                    input("Instructions: ")
                )

            elif c == "5":
                print("DELETE OPTION REACHED")
                file_name = input("Enter prescription filename: ").strip()
                print("CALLING SECURE DELETE...")
                system.secure_delete_file(user, file_name)

            elif c == "6":
                return

            else:
                print("Invalid option.")

        except (
            ValueError,
            PermissionError,
            FileNotFoundError,
            RuntimeError
        ) as e:
            print(f"ERROR: {e}")

def doctor_menu(system, user):
    while True:
        print("\n=== DOCTOR MENU ===")
        print("1. Write/update prescription")
        print("2. Read prescription")
        print("3. Logout")
        c = input("Choose: ").strip()
        try:
            if c == "1":
                system.write_prescription(
                    user, input("Patient email: "), input("Medicine: "),
                    input("Dosage: "), input("Duration: "),
                    input("Instructions: ")
                )
            elif c == "2":
                system.read_prescription(user, input("Patient email: "))
            elif c == "3":
                return
        except (ValueError, PermissionError, FileNotFoundError, RuntimeError) as e:
            print(f"ERROR: {e}")

def nurse_menu(system, user):
    while True:
        print("\n=== NURSE MENU ===")
        print("1. Read prescription")
        print("2. Update prescription")
        print("3. Logout")

        c = input("Choose: ").strip()

        try:
            if c == "1":
                patient_email = input("Patient email: ").strip()
                system.read_prescription(user, patient_email)

            elif c == "2":
                patient_email = input("Patient email: ").strip()

                print("\n=== UPDATE PRESCRIPTION ===")
                print("1. Change medicine")
                print("2. Change dosage")

                field = input("Choose field to update: ").strip()
                new_value = input("Enter new value: ").strip()

                if field == "1":
                    system.update_prescription_field(
                        user,
                        patient_email,
                        "medicine",
                        new_value
                    )

                elif field == "2":
                    system.update_prescription_field(
                        user,
                        patient_email,
                        "dosage",
                        new_value
                    )

                else:
                    print("Invalid option.")

            elif c == "3":
                return

        except (
            ValueError,
            PermissionError,
            FileNotFoundError,
            RuntimeError
        ) as e:
            print(f"ERROR: {e}")
def patient_menu(system, user):
    while True:
        print("\n=== PATIENT MENU ===")
        print("1. View my prescription")
        print("2. View my next visit")
        print("3. View my patient record")
        print("4. Logout")
        c = input("Choose: ").strip()
        try:
            if c == "1":
                system.read_prescription(user, user["email"])
            elif c in {"2", "3"}:
                system.view_record(user, user["email"])
            elif c == "4":
                return
        except (ValueError, PermissionError, FileNotFoundError, RuntimeError) as e:
            print(f"ERROR: {e}")

def main():
    system = HealthcareSystem()
    while True:
        print("\n========================================")
        print("     SECURE HEALTHCARE FILE SYSTEM")
        print("========================================")
        print("1. Patient Registration")
        print("2. Create Account (Admin / Doctor / Nurse / Patient)")
        print("3. Login")
        print("4. Run Security Demonstration")
        print("5. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            try:
                email = input("Email (username): ")
                password = getpass("Password: ")
                mobile = input("Mobile: ")
                system.create_account(email, password, "Patient", mobile)
            except ValueError as e:
                print(f"ERROR: {e}")
        elif choice == "2":
            create_account_menu(system)
        elif choice == "3":
            try:
                user = system.login(input("Email: "), getpass("Password: "))
                if user["role"] == "Admin":
                    admin_menu(system, user)
                elif user["role"] == "Doctor":
                    doctor_menu(system, user)
                elif user["role"] == "Nurse":
                    nurse_menu(system, user)
                else:
                    patient_menu(system, user)
            except PermissionError as e:
                print(f"LOGIN FAILED: {e}")
        elif choice == "4":
            system.security_demo()
        elif choice == "5":
            print("Goodbye.")
            break

if __name__ == "__main__":
    main()
