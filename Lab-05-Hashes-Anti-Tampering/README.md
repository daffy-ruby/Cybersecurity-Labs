# Lab 05 – Hashes & Anti-Tampering Mechanisms

**Course:** Cybersecurity Architecture, Design, and Secure Software Development  
**Programming Language:** Python 3  
**Focus:** Data Integrity, Message Authentication and Replay Attack Prevention

## 1. Project Overview

This project implements a Python-based integrity and anti-tampering system designed to protect sensitive healthcare application data and software files.

The application demonstrates cryptographic hashing, message authentication codes (HMAC), NONCE-based replay protection, and file integrity verification.

## 2. Learning Objectives

- Understand SHA-256 cryptographic hashing.
- Implement HMAC-SHA256 message authentication.
- Generate cryptographically secure secret keys.
- Implement NONCE-based replay attack prevention.
- Detect unauthorized file modifications.
- Understand the limitations of integrity mechanisms.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Application development |
| hashlib | SHA-256 hashing |
| hmac | Message authentication |
| secrets | Secure random key and NONCE generation |
| JSON | NONCE and hash storage |
| pathlib | File management |

## 4. Project Structure

- Source-Code – Python implementation
- Documentation – Assignment and final report
- Evidence – Hash verification evidence

## 5. Security Implementations

### Task 1 – SHA-256 Hashing
- Accepts user input.
- Generates SHA-256 hash.
- Displays original input and hash.

### Task 2 – HMAC Message Authentication
- Generates a random 256-bit secret key.
- Creates HMAC-SHA256 authentication codes.
- Verifies message integrity.
- Detects modified messages.

### Task 3 – NONCE Replay Protection
- Generates a unique random NONCE.
- Stores previously accepted NONCE values.
- Rejects reused NONCE values.
- Demonstrates replay attack detection.

### Task 4 – File Tampering Detection
- Generates SHA-256 file fingerprints.
- Stores trusted hash values.
- Recalculates hashes during verification.
- Detects unauthorized file modifications.

## 6. Execution

Run the application:

```bash
python lab5.py
```

The application provides an interactive menu for all four security tasks.

## 7. Expected Results

- SHA-256 hash successfully generated.
- Valid HMAC verification succeeds.
- Modified messages fail authentication.
- Reused NONCE values are rejected.
- Modified files trigger tampering alerts.

## 8. Security Considerations

- Secret keys must be stored securely.
- Secret keys and patient records must never be published.
- Trusted hash values must be protected against unauthorized modification.
- Production systems should use secure key management and persistent, concurrency-safe replay protection.

## 9. Conclusion

This lab demonstrates practical cryptographic integrity controls and anti-tampering techniques. It provides hands-on experience with SHA-256, HMAC, cryptographically secure randomness, replay attack prevention, and file integrity verification.
