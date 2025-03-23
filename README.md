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

## API Endpoints

### 1. Key Management
- **POST /generate-key**:  
  Generate an AES key of a specified size (128, 192, or 256 bits).  
  **Request Body**:
  ```json
  {
    "key_type": "AES",
    "key_size": 256
  }
  ```
  **Response**
  ```json
  {
  "key_id": "1",
  "key_value": "M2I0YjMyMTQ5NzYyMzI5OTkzYTYyMDA1N2NmZGU1OTM2MjE3MDNlYzY0NmMyMGQ0YjM2NzEzYzJhY2Y5YjFhNDFjYjY3YmE0Y2FlYzMwYmFkZDZkMTM1MDY0OWFmZDRmZjk1ZDZkMjA2"
  }
  ```

### 2. Encryption
- **POST /encrypt**:  
  Encrypt plaintext using AES encryption. 
  **Request Body**:
  ```json
  {
    "key_id": "1",
    "plaintext": "Hello, AES encryption!",
    "algorithm": "AES"
  }
  ```
  **Response**
  ```json
  {
    "ciphertext": "V6cMcV+kO5PL0as9sFsbXw=="
  }
  ```

### 3. Encryption
- **POST /decrypt**:  
  Decrypt ciphertext back to plaintext. 
  **Request Body**:
  ```json
  {
    "key_id": "1",
    "ciphertext": "V6cMcV+kO5PL0as9sFsbXw==",
    "algorithm": "AES"
  }
  ```
  **Response**
  ```json
  {
    "plaintext": "Hello, AES encryption!"
  }
  ```

### 4. Hashing
- **POST /generate-hash**:  
  Generate a cryptographic hash (SHA-256 or SHA-512) for input data. 
  **Request Body**:
  ```json
  {
    "data": "Hello, hash process!",
    "algorithm": "SHA-256"
  }
  ```
  **Response**
  ```json
  {
    "hash_value": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b1690c088b55fa6d7af413f4a3e5d3f",
    "algorithm": "SHA-256"
  }
  ```

  
- **POST /verify-hash**:  
  Verify if a given hash matches the input data.
  **Request Body**:
  ```json
  {
    "data": "Hello, hash process!",
    "hash_value": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b1690c088b55fa6d7af413f4a3e5d3f",
    "algorithm": "SHA-256"
  }
  ```
  **Response**
  ```json
  {
    "is_valid": true,
    "message": "Hash matches the data."
  }
  ```


### 5. User Authentication
- **POST /register**:  
  Register a new user with a username and password. 
  **Request Body**:
  ```json
  {
    "username": "user123",
    "password": "securepassword"
  }
  ```
  **Response**
  ```json
  {
    "message": "User registered successfully"
  }
  ```

- **POST /login**:  
  Authenticate a user by verifying their username and password. 
  **Request Body**:
  ```json
  {
    "username": "user123",
    "password": "securepassword"
  }
  ```
  **Response**
  ```json
  {
    "message": "Correct password. Login Successful"
  }
  ```
