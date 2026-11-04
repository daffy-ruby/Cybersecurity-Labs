# Lab 04: Input Validation, Secure Randomness & Injection Attack Prevention

**Course:** Cybersecurity Architecture, Design, and Secure Software Development  
**Project:** Healthcare Data Portal – Security Testing Module  
**Language:** Python  
**Repository:** Cybersecurity-Labs

## 1. Project Overview

This lab focuses on developing a secure input processing module for a healthcare data portal. The objective is to identify and prevent common application security vulnerabilities through input validation, secure coding practices, cryptographic randomness, and attack prevention techniques.

The implementation demonstrates how security controls protect applications against SQL Injection, Cross-Site Scripting (XSS), Directory Traversal, and predictable random tokens.

## 2. Objectives

- Implement email, filename, and file path validation.
- Demonstrate SQL Injection attacks and prevent them using parameterized queries.
- Prevent XSS through input sanitization and HTML output encoding.
- Understand formatting vulnerabilities and buffer overflow risks.
- Implement cryptographically secure random number generation.
- Compare Python's `random` and `secrets` modules.
- Analyze randomness distribution and Shannon entropy.
- Demonstrate token prediction risks using weak random seeds.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.8+ | Application development |
| Regular Expressions | Input validation |
| SQLite3 | Database and SQL Injection demonstration |
| Secrets | Cryptographically secure randomness |
| Random | Weak PRNG comparison |
| HTML | XSS output encoding |
| Matplotlib | Randomness distribution visualization |

## 4. Project Structure

```text
Lab-04-Input-Validation-Randomness/
│
├── README.md
│
├── Source-Code/
│   ├── secure_input_module.py
│   ├── app.py
│   └── file_validation.py
│
├── Documentation/
│   ├── Lab4_Assignment.docx
│   └── Lab4_Report.docx
│
└── Evidence/
    └── randomness_distribution.png
```

## 5. Security Implementations

### A. Input Validation
- Email address validation using Regex.
- Filename validation using whitelist rules.
- File path normalization and traversal protection.

### B. SQL Injection Prevention
- Demonstration of vulnerable SQL queries.
- Implementation of parameterized SQL statements.
- Comparison of vulnerable and secure database operations.

### C. Cross-Site Scripting Prevention
- Detection of potentially malicious HTML and JavaScript.
- Input sanitization.
- Output encoding using `html.escape()`.

### D. Secure Randomness
- Comparison of `random.randint()` and `secrets.randbelow()`.
- Secure session token generation.
- Password reset token generation.
- Weak seed predictability demonstration.

### E. Entropy Analysis
- Generation of 1,000 random samples.
- Distribution analysis.
- Shannon entropy calculation.
- Comparison of predictable and cryptographically secure randomness.

### F. Formatting and Buffer Overflow Awareness
- Demonstration of unsafe formatting concepts.
- Safe formatting techniques.
- Input length validation and resource limits.

## 6. Installation and Execution

**Prerequisites:**
- Python 3.8 or later.
- Matplotlib (optional, for visualization).

Install the optional dependency:

```bash
pip install matplotlib
```

Run the security module:

```bash
python secure_input_module.py
```

## 7. Testing and Evidence

The lab includes demonstrations of:

1. Valid and invalid email addresses.
2. Filename validation and hidden-file rejection.
3. Directory traversal attempts.
4. SQL Injection detection and prevention.
5. XSS detection and output encoding.
6. Weak seed versus CSPRNG comparison.
7
