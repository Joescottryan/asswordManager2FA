import os
from tkinter import Tk, Label, Entry, Button, Text, Frame, END, StringVar
from tkinter import ttk
from cryptography.fernet import Fernet
import hashlib
import re
import pyotp
import qrcode

# Hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Check if master password exists
def setup_master_password():
    if not os.path.exists("master_password.txt"):
        print("No master password found. Setting up a new master password.")
        master_password = input("Create a new master password: ")
        confirm_password = input("Confirm the master password: ")

        if master_password != confirm_password:
            print("Passwords do not match. Please restart the program to try again.")
            exit()

        # Save the hashed master password
        with open("master_password.txt", "w") as file:
            file.write(hash_password(master_password))
        print("Master password set successfully!")
    else:
        print("Master password already exists.")

# Verify the master password
def verify_master_password():
    if not os.path.exists("master_password.txt"):
        print("Master password file is missing. Please set up a new master password.")
        exit()

    master_password = input("Enter the master password: ")
    with open("master_password.txt", "r") as file:
        stored_hash = file.read()

    if hash_password(master_password) != stored_hash:
        print("Incorrect master password. Exiting.")
        exit()

# Generate a key and save it to a file (only run this once to create the key)
def generate_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)

# Load the encryption key
def load_key():
    with open("key.key", "rb") as key_file:
        return key_file.read()

# Encrypt a password
def encrypt_password(password, key):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode()).decode()

# Decrypt a password
def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_password.encode()).decode()

# Generate a 2FA secret and save it
def generate_2fa_secret():
    if not os.path.exists("2fa_secret.txt"):
        secret = pyotp.random_base32()
        with open("2fa_secret.txt", "w") as file:
            file.write(secret)
        print("2FA secret generated. Use this key in your authenticator app:", secret)
        display_qr_code(secret)
    else:
        with open("2fa_secret.txt", "r") as file:
            secret = file.read()
    return secret

# Display a QR code for the 2FA secret
def display_qr_code(secret):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="PasswordManager", issuer_name="MyApp")
    qr = qrcode.make(uri)
    qr.show()

# Verify the OTP entered by the user
def verify_otp(secret):
    totp = pyotp.TOTP(secret)
    otp = input("Enter the OTP from your authenticator app: ")
    if totp.verify(otp):
        print("2FA verification successful!")
        return True
    else:
        print("Invalid OTP. Exiting.")
        return False

# Add a new password
def add_password_gui(website, password, key, output_box):
    if not website or not password:
        output_box.insert(END, "Error: Website and password cannot be empty.\n")
        return
    encrypted_password = encrypt_password(password, key)
    with open("passwords.txt", "a") as file:
        file.write(f"{website} | {encrypted_password}\n")
    output_box.insert(END, f"Password for {website} added successfully!\n")

# Retrieve a password
def retrieve_password_gui(website, key, output_box):
    if not os.path.exists("passwords.txt"):
        output_box.insert(END, "No passwords stored yet.\n")
        return

    with open("passwords.txt", "r") as file:
        for line in file:
            stored_website, encrypted_password = line.strip().split(" | ")
            if stored_website == website:
                decrypted_password = decrypt_password(encrypted_password, key)
                output_box.insert(END, f"Password for {website}: {decrypted_password}\n")
                return
    output_box.insert(END, f"No password found for {website}.\n")

# List all stored websites
def list_websites_gui(output_box):
    if not os.path.exists("passwords.txt"):
        output_box.insert(END, "No passwords stored yet.\n")
        return

    output_box.insert(END, "Stored websites:\n")
    with open("passwords.txt", "r") as file:
        for line in file:
            website, _ = line.strip().split(" | ")
            output_box.insert(END, f"- {website}\n")

# Delete a password
def delete_password_gui(website, output_box):
    if not os.path.exists("passwords.txt"):
        output_box.insert(END, "No passwords stored yet.\n")
        return

    found = False
    with open("passwords.txt", "r") as file:
        lines = file.readlines()

    with open("passwords.txt", "w") as file:
        for line in lines:
            stored_website, _ = line.strip().split(" | ")
            if stored_website != website:
                file.write(line)
            else:
                found = True

    if found:
        output_box.insert(END, f"Password for {website} deleted successfully.\n")
    else:
        output_box.insert(END, f"No password found for {website}.\n")

# Audit weak passwords
def audit_weak_passwords(key, output_box):
    if not os.path.exists("passwords.txt"):
        output_box.insert(END, "No passwords stored yet.\n")
        return

    def is_password_weak(password):
        if len(password) < 8:
            return True, "Password is too short. Use at least 8 characters."
        if not re.search(r"[A-Z]", password):
            return True, "Add at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return True, "Add at least one lowercase letter."
        if not re.search(r"[0-9]", password):
            return True, "Add at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return True, "Add at least one special character."
        return False, ""

    output_box.insert(END, "Auditing passwords for weaknesses...\n")
    with open("passwords.txt", "r") as file:
        for line in file:
            website, encrypted_password = line.strip().split(" | ")
            decrypted_password = decrypt_password(encrypted_password, key)
            is_weak, suggestion = is_password_weak(decrypted_password)
            if is_weak:
                output_box.insert(END, f"Weak password found for {website}: {decrypted_password}\n")
                output_box.insert(END, f"Suggestion: {suggestion}\n")
    output_box.insert(END, "Password audit completed.\n")

# Detect reused passwords
def detect_reused_passwords(key, output_box):
    if not os.path.exists("passwords.txt"):
        output_box.insert(END, "No passwords stored yet.\n")
        return

    passwords = {}
    with open("passwords.txt", "r") as file:
        for line in file:
            website, encrypted_password = line.strip().split(" | ")
            decrypted_password = decrypt_password(encrypted_password, key)
            if decrypted_password in passwords:
                passwords[decrypted_password].append(website)
            else:
                passwords[decrypted_password] = [website]

    output_box.insert(END, "Checking for reused passwords...\n")
    for password, websites in passwords.items():
        if len(websites) > 1:
            output_box.insert(END, f"Password '{password}' is reused for: {', '.join(websites)}\n")
    output_box.insert(END, "Password reuse check completed.\n")

# Search for a password
def search_passwords(keyword, output_box):
    if not os.path.exists("passwords.txt"):
        output_box.insert(END, "No passwords stored yet.\n")
        return

    output_box.insert(END, f"Searching for '{keyword}'...\n")
    found = False
    with open("passwords.txt", "r") as file:
        for line in file:
            website, _ = line.strip().split(" | ")
            if keyword.lower() in website.lower():
                output_box.insert(END, f"Found: {website}\n")
                found = True
    if not found:
        output_box.insert(END, "No matching websites found.\n")

# GUI Setup with ttk.Notebook
def setup_gui():
    # Master Password Setup and Verification
    setup_master_password()
    verify_master_password()

    # 2FA Setup and Verification
    secret = generate_2fa_secret()
    if not verify_otp(secret):
        exit()

    generate_key()
    key = load_key()

    # Create the main window
    root = Tk()
    root.title("Password Manager")
    root.geometry("700x500")
    root.resizable(False, False)

    # Create Tabs
    notebook = ttk.Notebook(root)
    notebook.pack(pady=10, expand=True)

    # Create Frames for Tabs
    add_tab = Frame(notebook, width=700, height=500)
    retrieve_tab = Frame(notebook, width=700, height=500)
    list_tab = Frame(notebook, width=700, height=500)
    audit_tab = Frame(notebook, width=700, height=500)
    search_tab = Frame(notebook, width=700, height=500)

    add_tab.pack(fill="both", expand=True)
    retrieve_tab.pack(fill="both", expand=True)
    list_tab.pack(fill="both", expand=True)
    audit_tab.pack(fill="both", expand=True)
    search_tab.pack(fill="both", expand=True)

    # Add Tabs to Notebook
    notebook.add(add_tab, text="Add Password")
    notebook.add(retrieve_tab, text="Retrieve Password")
    notebook.add(list_tab, text="List Websites")
    notebook.add(audit_tab, text="Audit Passwords")
    notebook.add(search_tab, text="Search Passwords")

    # Add Password Tab
    Label(add_tab, text="Website:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
    website_entry = Entry(add_tab, width=30)
    website_entry.grid(row=0, column=1, padx=10, pady=10)

    Label(add_tab, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
    password_entry = Entry(add_tab, width=30)
    password_entry.grid(row=1, column=1, padx=10, pady=10)

    add_output_box = Text(add_tab, height=10, width=60, wrap="word", bg="#f0f0f0")
    add_output_box.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    Button(add_tab, text="Add Password", width=20, command=lambda: add_password_gui(
        website_entry.get(), password_entry.get(), key, add_output_box)).grid(row=2, column=0, columnspan=2, pady=10)

    # Retrieve Password Tab
    Label(retrieve_tab, text="Website:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
    retrieve_website_entry = Entry(retrieve_tab, width=30)
    retrieve_website_entry.grid(row=0, column=1, padx=10, pady=10)

    retrieve_output_box = Text(retrieve_tab, height=10, width=60, wrap="word", bg="#f0f0f0")
    retrieve_output_box.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    Button(retrieve_tab, text="Retrieve Password", width=20, command=lambda: retrieve_password_gui(
        retrieve_website_entry.get(), key, retrieve_output_box)).grid(row=1, column=0, columnspan=2, pady=10)

    # List Websites Tab
    list_output_box = Text(list_tab, height=20, width=60, wrap="word", bg="#f0f0f0")
    list_output_box.pack(padx=10, pady=10)

    Button(list_tab, text="List Websites", width=20, command=lambda: list_websites_gui(list_output_box)).pack(pady=10)

    # Audit Passwords Tab
    audit_output_box = Text(audit_tab, height=20, width=60, wrap="word", bg="#f0f0f0")
    audit_output_box.pack(padx=10, pady=10)

    Button(audit_tab, text="Audit Weak Passwords", width=20, command=lambda: audit_weak_passwords(
        key, audit_output_box)).pack(pady=10)

    Button(audit_tab, text="Detect Reused Passwords", width=20, command=lambda: detect_reused_passwords(
        key, audit_output_box)).pack(pady=10)

    # Search Passwords Tab
    Label(search_tab, text="Search Keyword:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
    search_entry = Entry(search_tab, width=30)
    search_entry.grid(row=0, column=1, padx=10, pady=10)

    search_output_box = Text(search_tab, height=10, width=60, wrap="word", bg="#f0f0f0")
    search_output_box.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    Button(search_tab, text="Search Passwords", width=20, command=lambda: search_passwords(
        search_entry.get(), search_output_box)).grid(row=1, column=0, columnspan=2, pady=10)

    # Run the GUI
    root.mainloop()

if __name__ == "__main__":
    setup_gui()