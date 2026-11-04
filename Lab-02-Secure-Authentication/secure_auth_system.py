import os
import json
import time
import datetime
import re
import secrets
import bcrypt
import jwt

def evaluate_password_strength(password):
    if len(password) < 8:
        return "Weak", "Password must be at least 8 characters long."
    
    if re.match(r'^[a-zA-Z]+[0-9]+$', password) and len(password) < 12:
        return "Weak", "Avoid simple combinations of letters followed by numbers."

    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[\W_]', password))

    score = sum([has_upper, has_lower, has_digit, has_special])

    if score >= 4 and len(password) >= 12:
        return "Strong", "Strong password."
    elif score >= 3 and len(password) >= 8:
        return "Moderate", "Moderate password. Add special characters for higher strength."
    else:
        return "Weak", "Must include uppercase, lowercase, numbers, and special characters."


class RateLimiter:
    def __init__(self, max_attempts=3, window_seconds=60, lockout_seconds=300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.tracker = {}

    def is_allowed(self, identifier):
        now = time.time()
        record = self.tracker.get(identifier, {"attempts": [], "locked_until": 0})

        if now < record["locked_until"]:
            remaining = int(record["locked_until"] - now)
            return False, f"Account locked due to failed attempts. Try again in {remaining} seconds."

        record["attempts"] = [t for t in record["attempts"] if now - t < self.window_seconds]

        if len(record["attempts"]) >= self.max_attempts:
            record["locked_until"] = now + self.lockout_seconds
            self.tracker[identifier] = record
            return False, f"Rate limit exceeded. Account locked out for {self.lockout_seconds // 60} minutes."

        self.tracker[identifier] = record
        return True, "Allowed."

    def record_failed_attempt(self, identifier):
        now = time.time()
        if identifier not in self.tracker:
            self.tracker[identifier] = {"attempts": [], "locked_until": 0}
        self.tracker[identifier]["attempts"].append(now)

    def reset_attempts(self, identifier):
        if identifier in self.tracker:
            del self.tracker[identifier]


class UnifiedAuthSystem:
    def __init__(self, jwt_secret="SUPER_SECRET_KEY"):
        self.passwd_file = "passwd.json"
        self.shadow_file = "shadow.json"
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = "HS256"
        
        self.rate_limiter = RateLimiter(max_attempts=3, window_seconds=60, lockout_seconds=300)
        self.system_locked_down = False
        self.global_revocation_timestamp = 0

        self._initialize_storage()

    def _initialize_storage(self):
        if not os.path.exists(self.passwd_file):
            with open(self.passwd_file, "w") as f:
                json.dump({}, f)
        if not os.path.exists(self.shadow_file):
            with open(self.shadow_file, "w") as f:
                json.dump({}, f)
            try:
                os.chmod(self.shadow_file, 0o600)
            except OSError:
                pass

    def _load_data(self, filepath):
        with open(filepath, "r") as f:
            return json.load(f)

    def _save_data(self, filepath, data):
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        if filepath == self.shadow_file:
            try:
                os.chmod(self.shadow_file, 0o600)
            except OSError:
                pass

    def _generate_next_uid(self):
        passwd_db = self._load_data(self.passwd_file)
        if not passwd_db:
            return "1001"
        existing_uids = [int(uid) for uid in passwd_db.keys()]
        return str(max(existing_uids) + 1)

    def register_user(self, username, password):
        strength, msg = evaluate_password_strength(password)
        if strength == "Weak":
            return None, f"Registration failed: {msg}"

        passwd_db = self._load_data(self.passwd_file)
        for user_meta in passwd_db.values():
            if user_meta.get("username", "").lower() == username.lower():
                return None, "Registration failed: Username already exists."

        uid = self._generate_next_uid()
        salt = bcrypt.gensalt(rounds=12)
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        passwd_db[uid] = {
            "uid": uid,
            "username": username,
            "created_at": str(datetime.datetime.now())
        }
        self._save_data(self.passwd_file, passwd_db)

        shadow_db = self._load_data(self.shadow_file)
        shadow_db[uid] = {
            "uid": uid,
            "password_hash": hashed_pw,
            "password_history": [hashed_pw]
        }
        self._save_data(self.shadow_file, shadow_db)

        return uid, f"User '{username}' registered successfully! Assigned UID: {uid}"

    def login(self, uid, password):
        allowed, status_msg = self.rate_limiter.is_allowed(uid)
        if not allowed:
            return False, None, status_msg

        shadow_db = self._load_data(self.shadow_file)
        if uid not in shadow_db:
            self.rate_limiter.record_failed_attempt(uid)
            return False, None, "Invalid UID or password."

        stored_hash = shadow_db[uid]["password_hash"]
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            self.rate_limiter.reset_attempts(uid)
            token, token_msg = self.generate_token(uid)
            return True, token, "Login successful!"
        else:
            self.rate_limiter.record_failed_attempt(uid)
            return False, None, "Invalid UID or password."

    def reset_password(self, uid, new_password):
        shadow_db = self._load_data(self.shadow_file)
        if uid not in shadow_db:
            return False, "User identifier not found."

        strength, msg = evaluate_password_strength(new_password)
        if strength == "Weak":
            return False, f"Password rejected. Reason: {msg}"

        user_shadow = shadow_db[uid]

        for old_hash in user_shadow["password_history"]:
            if bcrypt.checkpw(new_password.encode('utf-8'), old_hash.encode('utf-8')):
                return False, "This password already exists. Please use new password."

        new_salt = bcrypt.gensalt(rounds=12)
        new_hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), new_salt).decode('utf-8')

        user_shadow["password_hash"] = new_hashed_pw
        user_shadow["password_history"].append(new_hashed_pw)
        self._save_data(self.shadow_file, shadow_db)

        return True, "Password reset successfully! You can now log in with your new password."

    def generate_token(self, uid, ttl_seconds=300):
        if self.system_locked_down:
            return None, "System is under emergency lockdown. Tokens cannot be generated."

        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": uid,
            "iat": now,
            "exp": now + datetime.timedelta(seconds=ttl_seconds),
            "jti": secrets.token_hex(8)
        }
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        return token, "Token issued."

    def validate_token(self, token):
        if self.system_locked_down:
            return False, "Access Denied: System is currently in emergency lockdown mode."

        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            token_iat = payload.get("iat")
            if token_iat < self.global_revocation_timestamp:
                return False, "Access Denied: Token invalidated by global revocation."

            return True, f"Token valid for UID: {payload['sub']}"
        except jwt.ExpiredSignatureError:
            return False, "Access Denied: Token has expired."
        except jwt.InvalidTokenError:
            return False, "Access Denied: Invalid token."

    def trigger_emergency_shutdown(self, reason="Attack Detected"):
        self.system_locked_down = True
        self.global_revocation_timestamp = time.time()
        print(f"\n[SECURITY ALERT] EMERGENCY SHUTDOWN TRIGGERED! Reason: {reason}")
        print("ALL ACTIVE TOKENS REVOKED SIMULTANEOUSLY.\n")