#!/usr/bin/env python3
import sys
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import getpass
from fuzzywuzzy import process
BACKEND = default_backend()
SALT_SIZE = 16  # 128-bit salt
KEY_SIZE = 32  # 256-bit key
NONCE_SIZE = 12  # 96-bit nonce
TAG_SIZE = 16
ITERATIONS = 100000
FILE_PATH = "Passwords.txt"

def write_to_file(text):
    with open(FILE_PATH, 'a') as file:
        file.write(f"{text}\n")


def delete_from_file(line_num):
    with open(FILE_PATH, 'r') as file:
        lines = file.readlines()
    
    with open(FILE_PATH, 'w') as file:
        for index, line in enumerate(lines):
            if index !=  line_num:
                file.write(line)

def find_closest_string(target, string_list):
    closest_match = process.extractOne(target, string_list)
    return closest_match[0]


class Encryptor:
    @staticmethod
    def generate_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=ITERATIONS,
            backend=BACKEND
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_file(file_path, password):
        """Encrypt the file and save it with .enc extension."""
        salt = os.urandom(SALT_SIZE)
        key = Encryptor.generate_key(password, salt)
        nonce = os.urandom(NONCE_SIZE)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=BACKEND
        )
        
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f:
                plaintext = f.read()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        with open(file_path + '.enc', 'wb') as f:
            f.write(salt + nonce + encryptor.tag + ciphertext)

        os.remove(file_path)
        
        print(f"File {file_path} encrypted successfully and plaintext deleted.")

    @staticmethod
    def decrypt_file(file_path, password):
        """Decrypt the file and save the result without .enc extension."""
        with open(file_path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            tag = f.read(TAG_SIZE)
            ciphertext = f.read()
        
        key = Encryptor.generate_key(password, salt)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=BACKEND
        )
        
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print(f"Decryption failed: {e}")
            raise Exception
        
        with open(file_path.replace('.enc', ''), 'wb') as f:
            f.write(plaintext)
        
        print(f"File {file_path} decrypted successfully.")
        return True

def auth_decrypt():
    """Decrypts the file after the correct password is entered otherwise terminates the program"""
    count = 0
    valid = False

    ### Checks if file passwords file doesnt exist at all
    if not os.path.isfile(FILE_PATH) and not os.path.isfile(FILE_PATH+'.enc'):
        print("Passwords.txt file not found >>>\nCreating a Passwords.txt file for you...")
        with open(FILE_PATH, 'w') as f:
            pass
        password = getpass.getpass(prompt="Set your master password (main password to decrypt text file):")
        Encryptor.encrypt_file(FILE_PATH, password)
    ### Checks if you have an unencrypted file
    elif not os.path.isfile(FILE_PATH+'.enc'):
        password = getpass.getpass(prompt='Set your master password (main password to decrypt text file): ')
        Encryptor.encrypt_file(FILE_PATH, password)
        print("===Successfully recovered Passwords.txt file and encrypted it===")

    while count < 3 and valid == False:
        password = getpass.getpass(prompt='Enter password to open encrypted file: ')
        try:
            valid = Encryptor.decrypt_file(FILE_PATH+'.enc', password)
        except Exception as e:
            print(f"Incorrect password: {e}")
            count += 1
    if count == 3:
        quit()
    return password

def file_reader(file_path):
    with open(file_path, "r") as file:
    #Read all the lines from the file
        lines = [line.strip() for line in file]
    return lines

def text_parser(lines):
    string_list = lines
    before_comma = [s.split(',')[0].strip() for s in string_list]
    after_comma = [s.split(',', 1)[1].strip() for s in string_list]
    return before_comma, after_comma

    

def menu():
    choice = int(input("1). Add account \n2). Delete account\n3). Save changes\n:"))
    if choice == 1:
        account = input("Enter the account and/or a hint:")
        password = getpass.getpass(prompt='Enter password: ')
        write_to_file(f"{account}, {password}")
        print(f">>>{account} has been written to the file")
        return False
    elif choice == 2:
        lines = file_reader(FILE_PATH)
        before_comma, _ = text_parser(lines)
        print(before_comma)
        account = input("Enter account to delete:")
        closest = find_closest_string(account, before_comma)
        line_num = before_comma.index(closest)
        delete_from_file(line_num)
        print(f"{closest} account deleted...")
        return False
    elif choice == 3:
        return True


if __name__ == "__main__":
    print('IF YOU WANT TO ADD PASSWORDS QUICKLY \n1).CREATE A "Passwords.txt" file or just "Passwords" (on windows)\n2).Insert passwords in the format "label,password" (no spaces) and seperate each entry with a new line\n3).Open either Adder or Crimson\nOr simply just use the adder program and add them 1 by 1\nTIP - Make sure adder and crimson are in the same folder preferably a designated passwords folder')
    print("\n"*3+"Resuming program...")
    encryptor = Encryptor()
    master_pass = auth_decrypt()
    valid = False
    while valid == False:
        valid = menu()
    encryptor.encrypt_file(FILE_PATH, master_pass)
