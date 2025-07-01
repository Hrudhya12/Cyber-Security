import sqlite3
from cryptography.fernet import Fernet
import getpass
import os

def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    print("Encryption key generated and saved to key.key")

def load_key():
    try:
        if not os.path.exists("key.key"):
            raise FileNotFoundError("Encryption key not found. Generate it first.")
        return open("key.key", "rb").read()
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

def encrypt_password(password, key):
    try:
        f = Fernet(key)
        return f.encrypt(password.encode())
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_password(encrypted_password, key):
    try:
        f = Fernet(key)
        return f.decrypt(encrypted_password).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# --- DATABASE SETUP ---
def create_database():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service_name TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# --- CRUD FUNCTIONS ---
def add_password(service, username, password):
    try:
        key = load_key()
        if not key:
            return
        encrypted_password = encrypt_password(password, key)
        if not encrypted_password:
            return
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO passwords (service_name, username, password) VALUES (?, ?, ?)',
                       (service, username, encrypted_password))
        conn.commit()
        conn.close()
        print("Password added successfully.")
    except Exception as e:
        print(f"Error adding password: {e}")

def retrieve_password(service, username):
    try:
        key = load_key()
        if not key:
            return
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM passwords WHERE service_name = ? AND username = ?',
                       (service, username))
        result = cursor.fetchone()
        conn.close()
        if result:
            decrypted = decrypt_password(result[0], key)
            if decrypted:
                print(f"Retrieved password: {decrypted}")
        else:
            print("No password found for that service/username.")
    except Exception as e:
        print(f"Error retrieving password: {e}")

def update_password(service, username, new_password):
    try:
        print("Starting update operation")
        key = load_key()
        if not key:
            print("Key could not be loaded. Update aborted.")
            return
        print("Key loaded")
        encrypted_password = encrypt_password(new_password, key)
        if not encrypted_password:
            print("Encryption failed. Update aborted.")
            return
        print("Password encrypted")
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE passwords SET password = ? WHERE service_name = ? AND username = ?',
                       (encrypted_password, service, username))
        if cursor.rowcount == 0:
            print("No matching entry found to update.")
        else:
            print("Password updated successfully.")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error updating password: {e}")

def delete_password(service, username):
    try:
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM passwords WHERE service_name = ? AND username = ?',
                       (service, username))
        conn.commit()
        conn.close()
        print("Password deleted.")
    except Exception as e:
        print(f"Error deleting password: {e}")

# --- MAIN FUNCTION ---
def main():
    print("Welcome to the Python Password Manager")
    create_database()

    if not os.path.exists("key.key"):
        choice = input("No encryption key found. Generate one now? (y/n): ").strip().lower()
        if choice == "y":
            generate_key()
        else:
            print("Key is required to continue.")
            return

    while True:
        print("\nChoose an option: add, retrieve, update, delete, exit")
        choice = input("Your choice: ").strip().lower()

        if choice == "add":
            service = input("Service Name: ")
            print(f"Got service: {service}")
            username = input("Username: ")
            print(f"Got username: {username}")
            password = input("Password: ")
            print(f"Got password")
            add_password(service, username, password)

        elif choice == "retrieve":
            service = input("Service Name: ")
            username = input("Username: ")
            retrieve_password(service, username)

        elif choice == "update":
            service = input("Service Name: ")
            print(f"Got service: {service}")
            username = input("Username: ")
            print(f"Got username: {username}")
            new_password = input("New Password: ")
            print(f"Got new password")
            update_password(service, username, new_password)

        elif choice == "delete":
            service = input("Service Name: ")
            username = input("Username: ")
            confirm = input("Are you sure you want to delete this entry? (y/n): ").strip().lower()
            if confirm == "y":
                delete_password(service, username)

        elif choice == "exit":
            print("Exiting Password Manager. Stay secure!")
            break

        else:
            print("Unknown command. Try again.")

if __name__ == "__main__":
    main()