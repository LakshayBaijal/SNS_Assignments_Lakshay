# Lab Assignment 2:
## Secure Telemedical Conference using Digital Signature

## Team ID - 1
### Member 1 
- Name: Lakshay Baijal 
- Roll Number: 2024202006

[Screencast from 2025-03-08 15-09-05.webm](https://github.com/user-attachments/assets/dd8374cb-2534-4a89-94b6-b40d67d183a0)

## Overview

This project implements a secure telemedical conferencing system using cryptographic protocols, including ElGamal for authentication and AES-256 encryption for secure message communication. The implementation ensures confidentiality, integrity, and authentication between a doctor and multiple patient devices.

## Features

- Cryptographic Authentication: Secure key exchange and authentication using ElGamal Cryptosystem.

- AES-256 Encryption: Secure message and group key encryption using AES in CBC mode.

- Digital Signatures: Message integrity verified using ElGamal digital signatures.

- Timestamp Validation: Ensures freshness of messages with a timestamp verification within a permissible delay.

- Group Key Management: Dynamic group key computation and distribution to active patients only.

- Broadcast Messaging: Doctor broadcasts encrypted messages to authenticated and active patients.

- Dynamic Group Management:

 Patients going offline will not receive broadcast messages.

 New patients joining during an ongoing broadcast are queued for subsequent broadcasts.

 The system can rekey group communication dynamically based on new patient threshold (x).


## Cryptographic Operations

- ElGamal Key Exchange: Securely generates and exchanges session keys.

- ElGamal Signature: Verifies message integrity and authentication.

- AES-256 (CBC Mode): Encrypts and Decrypts broadcast messages and group keys.

- SHA256 Hashing: Ensures message integrity.


## Implementation:

- Create Virtual Environment for Python
```bash
python3 -m venv venv
source venv/bin/activate
```

- Install pycryptodome
```bash
pip install pycryptodome
```





