import json
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def create_key(password: str):
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def load_key():
    try:
        with open("key.key", "rb") as key_file:
            key = key_file.read()
            return key
    except FileNotFoundError:
        password = input("Enter a password to create a new key: ").encode()
        key = create_key(password)
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        return key

def view():
    try:
        with open('passwords.txt', 'r') as f:
            data = json.load(f)
            for account, password in data.items():
                print(f"Account: {account} | Password: {password}")
    except FileNotFoundError:
        print("No passwords found.")

def add():
    name = input('Account Name: ')
    pwd = input("Password: ")

    try:
        with open('passwords.txt', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    data[name] = pwd
    with open('passwords.txt', 'w') as f:
        json.dump(data, f)

while True:
    mode = input("Would you like to add a new password or view existing ones (view, add), press q to quit? ").lower()
    if mode == "q":
        break

    if mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid mode.")
        continue