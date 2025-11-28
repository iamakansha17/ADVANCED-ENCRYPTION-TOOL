# ADVANCED ENCRYPTION TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: AKANSHA JADHAV

*INTERN ID*: CT04DR1398

*DOMAIN*: CYBERSECURITY AND ETHICAL HACKING

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH


# TASK-4: ADVANCED ENCRYPTION TOOL

This module implements AES-256 (Advanced Encryption Standard) encryption. It ensures data confidentiality by converting plaintext into unreadable ciphertext. The Python script uses the cryptography library to derive strong keys from passwords and secure files.

This tool encrypts and decrypts files using AES-256-GCM with password-derived keys.
A secure and user-friendly encryption utility designed for penetration testers, cybersecurity researchers, and privacy-focused users.
This tool provides AES-256-GCM authenticated encryption, secure password-based key derivation (PBKDF2-HMAC-SHA256), a Tkinter GUI, and a full command-line interface (CLI).

## Features
- AES-256-GCM (authenticated encryption)
- PBKDF2-HMAC-SHA256 key derivation with random salt (per-file)
- Tkinter GUI and CLI mode
- Simple file header for easy decryption

## Requirements
pip install cryptography

## GUI usage
python advanced_encryption_tool.py
- Select file, enter password, click Encrypt or Decrypt.

## CLI usage
Encrypt:
python advanced_encryption_tool.py enc mypassword file.txt file.txt.enc

Decrypt:
python advanced_encryption_tool.py dec mypassword file.txt.enc file.txt.dec

## Security notes
- Use a strong password/passphrase.
- Keep password secret and share via secure channels.
- AES-256-GCM provides both confidentiality and integrity.


#  File format & security notes:
  *  File header contains 4-byte magic (b'AE01') + 16-byte salt + 12-byte nonce + ciphertext.
     <img width="732" height="89" alt="Image" src="https://github.com/user-attachments/assets/b63f1bdc-b18e-4e0f-ba3d-d82004081666" />
  *  AES-GCM provides confidentiality and integrity (so tampering will fail during decryption).
  *  PBKDF2 with 200k iterations is used to slow brute-force (increase iterations if you need higher CPU cost).
     It turns a password into a strong AES key:
     <img width="709" height="52" alt="Image" src="https://github.com/user-attachments/assets/75779f81-d7d7-4132-835a-af07d39fc6cf" />
  *  Never reuse the same salt+nonce for the same key — code uses random per-file salt & nonce.
  *  If you need to share encrypted files, share only the encrypted .enc file and the password through a different channel (never in the same message).


#  ✅ Summary (Simple Version)

- Magic (AE01) tells the program “This is one of our encrypted files.”
- Salt ensures password → unique key.
- Nonce ensures encryption is safe and non-repeating.
- AES-GCM ensures both secrecy and tamper-proof security.
- PBKDF2 makes brute-force attacks slow.
- Salt + nonce must never repeat for the same key.
- Share the encrypted file and password separately.



#  OUTPUT:
*advanced_encryption_tool.py*
<img width="1727" height="897" alt="Image" src="https://github.com/user-attachments/assets/dbb993b1-5983-45f7-8838-35177779f146" />
