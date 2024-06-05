from cryptography.fernet import Fernet # type: ignore
import os
import hashlib
import base64

'''
master password = panda
'''

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    if not os.path.exists("key.key"):
        write_key()
    with open("key.key", "rb") as key_file:
        key = key_file.read()
    return key

def get_fernet(master_pwd: str) -> Fernet:
    key = load_key()
    # Combine the key with the master password and hash it
    combined = key + master_pwd.encode()
    hashed_key = hashlib.sha256(combined).digest()
    # Encode the hash as base64 to create a valid Fernet key
    derived_key = base64.urlsafe_b64encode(hashed_key)
    return Fernet(derived_key)

master_pwd = input("What is the master password? ")
fer = get_fernet(master_pwd)

def view():
    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split("|")
            print("User: ", user, "| Password: ", fer.decrypt(passw.encode()).decode())

def add():
    name = input('Account Name: ')
    pwd = input("Password: ")

    with open('passwords.txt', 'a') as f:
        f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")

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
