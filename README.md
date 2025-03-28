# Password Manager with 2FA THIS IS JUST A PROJECT Not intended for real use

This is a Python-based password manager with Two-Factor Authentication (2FA) for enhanced security. It allows you to securely store, retrieve, and manage your passwords, with additional features like password auditing and 2FA for secure access.

---

## Features
- **Master Password Protection**: Secure access to the password manager using a master password.
- **Two-Factor Authentication (2FA)**: Adds an extra layer of security using TOTP (Time-based One-Time Passwords).
- **Password Management**:
  - Add, retrieve, delete, and search passwords.
  - List all stored websites.
- **Password Auditing**:
  - Detect weak passwords and provide suggestions for improvement.
  - Identify reused passwords across different websites.
- **Tabbed GUI Interface**: A clean and organized interface using `tkinter`.

---

## Requirements
- **Python Version**: Python 3.x
- **Libraries**:
  - `cryptography`
  - `pyotp`
  - `qrcode`

---



   Install Dependencies: Install the required libraries using the requirements.txt file:

pip install -r requirements.txt

Run the Program: Start the password manager by running:
python main.py


## Usage
First-Time Setup:

The program will prompt you to create a master password.
It will also generate a 2FA secret and display a QR code. Scan the QR code using an authenticator app (e.g., Google Authenticator, Authy).
Login:

Enter your master password and the OTP from your authenticator app to access the password manager.
Manage Passwords:

Use the GUI to add, retrieve, delete, and search passwords.
Audit your passwords for weaknesses or reuse.

## Notes
The program generates the following files during runtime:
master_password.txt: Stores the hashed master password.
2fa_secret.txt: Stores the 2FA secret key.
passwords.txt: Stores encrypted passwords.
These files are excluded from the repository for security reasons.


## Security Best Practices
Do Not Share Sensitive Files: Ensure master_password.txt, 2fa_secret.txt, and passwords.txt are not uploaded to public repositories.
Regenerate 2FA Secret if Compromised: Delete 2fa_secret.txt to reset the 2FA setup.
Use a Strong Master Password: Choose a strong and unique master password.


## Acknowledgments
Libraries Used:
cryptography
pyotp
qrcode



---
