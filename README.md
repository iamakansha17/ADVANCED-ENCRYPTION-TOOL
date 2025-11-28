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
    <img width="863" height="139" alt="Image" src="https://github.com/user-attachments/assets/11b8a60d-30f9-4f1a-bb1b-1fa7d6999404" />
  *  AES-GCM provides confidentiality and integrity (so tampering will fail during decryption).
  *  PBKDF2 with 200k iterations is used to slow brute-force (increase iterations if you need higher CPU cost).
  *  Never reuse the same salt+nonce for the same key — code uses random per-file salt & nonce.
  *  If you need to share encrypted files, share only the encrypted .enc file and the password through a different channel (never in the same message).



#  OUTPUT:
*advanced_encryption_tool.py*
<img width="1727" height="897" alt="Image" src="https://github.com/user-attachments/assets/dbb993b1-5983-45f7-8838-35177779f146" />
