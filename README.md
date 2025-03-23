# Cryptographic API

This project implements a **Cryptographic API** using the Flask framework in Python. The API provides functionalities for symmetric encryption and decryption, hashing, hash verification, and user authentication. It is designed to be secure, user-friendly, and easy to integrate into applications requiring cryptographic operations.

---

## Features

1. **Key Management**:
   - Generate AES encryption keys of specified sizes (128, 192, or 256 bits).

2. **Encryption and Decryption**:
   - Encrypt plaintext using AES encryption in CBC mode.
   - Decrypt ciphertext back to plaintext using the same AES key.

3. **Hashing**:
   - Generate cryptographic hashes (SHA-256 or SHA-512) for input data.
   - Verify if a given hash matches the input data.

4. **User Authentication**:
   - Register new users with a username and password (passwords are securely hashed using bcrypt).
   - Authenticate users by verifying their username and password during login.

5. **API Documentation**:
   - Swagger UI is integrated for interactive API documentation.
   - Users can test endpoints directly from the Swagger interface.

---

## Tools and Libraries Used

- **Flask**: A lightweight web framework for building the API.
- **cryptography**: A library for cryptographic operations (AES encryption/decryption).
- **hashlib**: A library for generating cryptographic hashes (SHA-256, SHA-512).
- **bcrypt**: A library for secure password hashing and verification.
- **Flasgger**: A tool for generating Swagger documentation for Flask APIs.
- **Railway**: A cloud platform for deploying the Flask application.

---

## Getting Started

### Prerequisites

- Python 3.8 or higher.
- Pip (Python package installer).

### Installation

1. Clone the repository
2. All the other instructions are given inside the `Milestone 2`
