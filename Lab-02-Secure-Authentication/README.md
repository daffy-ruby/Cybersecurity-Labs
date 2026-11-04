# Lab 02 – Secure Authentication System

## Course
Cybersecurity Architecture, Design, and Secure Software Development

## Overview
This project implements a layered authentication system using password-based authentication, multi-factor authentication (MFA), and JSON Web Tokens (JWT).

## Task 1 – Password-Based Authentication
- Bcrypt salted password hashing
- Password strength validation
- Failed login tracking
- Account lockout
- Password history management

## Task 2 – Multi-Factor Authentication
- Secure six-digit OTP generation
- File-based OTP storage
- OTP expiration and attempt limits
- Google Authenticator integration
- TOTP verification

## Task 3 – Token-Based Authentication
- JWT generation
- Token validation
- Token expiration
- Individual token revocation
- Emergency token revocation

## Task 4 – Threat Analysis
- OTP interception and reuse
- JWT forgery and replay attacks
- Brute-force and password guessing
- Security mitigation strategies

## Technologies Used
- Python
- Bcrypt
- PyJWT
- PyOTP
- QRCode
- JSON
- SHA-256

## Security Objectives
Confidentiality, Integrity, and Accountability.

## Learning Outcomes
Understanding secure authentication, MFA implementation, password security, token lifecycle management, and authentication threat mitigation.
