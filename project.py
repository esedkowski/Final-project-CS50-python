from hashlib import blake2b
import csv
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import maskpass
import re
import sys
from os.path import exists

#https://docs.python.org/3/library/hashlib.html#hash-algorithms
#https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet

def sign_up(deposit):
    login, login_hash = get_login()
    password, password_hashed = get_password()
    with open("passwords/passwords.csv", "a", newline="") as pass_stor:
        writer = csv.writer(pass_stor)
        writer.writerow([login_hash, password_hashed])
    login_new_hash = blake2b(login.encode(), digest_size=32).hexdigest()
    path = "accounts/" + login_new_hash
    f = gen_key(login, password)
    new_account_data(path, login, deposit, f)
    print("Sign up complited")

def new_account_data(path, login, balance, key):
    login = key.encrypt(bytes(login, "utf-8"))
    balance = key.encrypt(bytes(str(balance), "utf-8"))
    with open(path, "w", newline="") as account:
        data = str(login) + "," + str(balance)
        account.write(data)

def get_login():
    correct = True
    while True:
        with open("passwords/passwords.csv", "r") as login_stor:
            login = input("Login: ")
            login_hash = blake2b(login.encode()).hexdigest()
            for line in login_stor:
                if login_hash == line.split(",")[0]:
                    print("Login already taken :(")
                    correct = False
                    break
                else:
                    correct = True
        if correct == True:
            break
    return [login, login_hash]
            
def get_password():
    while True:
        password = input()
        password = maskpass.askpass(prompt="Password: ", mask="*")
        if not re.search("[a-z]" ,password):
            print("missing lowercase character")
        elif not re.search("[A-Z]" ,password):
            print("missing uppercase character")
        elif not re.search(r"[!@#$%^&*()\[\]\{\}:;\"\',\./\?\<\>]", password):
            print("missing special character")
        elif not re.search("[1-9]", password):
            print("missing number")
        else:
            break
    password_hashed = blake2b(password.encode()).hexdigest()
    return [password, password_hashed]

def veryficaton(login, password):
    with open("passwords/passwords.csv") as pass_stor:
        login = blake2b(login.encode()).hexdigest()
        password = blake2b(password.encode()).hexdigest()
        ver = login + "," + password
        for line in pass_stor:
            if line.strip("\n") == ver:
                return True
    return False

def gen_key(login, password):
    password_in_bytes = bytes(password, "utf-8")
    login_in_bytes = bytes(login, "utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=login_in_bytes, iterations=390000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password_in_bytes))
    return Fernet(key)
    #token = f.encrypt(b"Secret message!")
    #print(str(f1.decrypt(token)).strip("b'"))

def sign_in():
    login = input("Login: ")
    password = input()
    password = maskpass.askpass(prompt="Password: ", mask="*")
    if veryficaton(login, password):
        login_hashed = blake2b(login.encode(), digest_size=32).hexdigest()
        path = "accounts/" + login_hashed
        with open(path, "r") as account:
            name, balance = account.read().split(",")
        f = gen_key(login, password)
        balance = int(str(f.decrypt(balance.strip("b'"))).strip("b'"))
        name = str(f.decrypt(name.strip("b'"))).strip("b'")

        path_recived = "accounts/recived" + login_hashed
        if exists(path_recived):
            print("aaaa")
            with open(path_recived, "r") as file:
                for line in file:
                    balance += int(line)
            new_account_data(path, login, balance, f)
            os.remove(path_recived)


        del f
        return [name, balance]
    print("wrong login and/or password")
    return [False, False]

def transfer(user, amount, reciver, current_balance):
    if amount > current_balance:
        print("Lack of sufficient funds in the account")
        return False
    with open("passwords/passwords.csv", "r") as login_stor:
        reciver_hashed = blake2b(reciver.encode()).hexdigest()
        appear = False
        for line in login_stor:
            if reciver_hashed == line.split(",")[0]:
                appear = True
                break
        if appear == False:
            print("No such account exist")
            return False

    password = "Error - wrong password"
    with open("passwords/passwords.csv", "r") as login_stor:
        user_hashed = blake2b(user.encode()).hexdigest()
        for line in login_stor:
            if user_hashed == line.split(",")[0]:
                for attempt in range(0,3):
                    password = input()
                    password = maskpass.askpass(prompt="Repeat your password: ", mask="*")
                    password_hashed = blake2b(password.encode()).hexdigest()
                    if password_hashed == line.split(",")[1].strip("\n"):
                        print("password correct")
                        break 
                    elif attempt == 2:
                        print("Too many wrong attemps")
                        return False
                    else:
                        print("Incorrect password!")
                break
    
    key = gen_key(user, password)
    path = "accounts/" + blake2b(user.encode(), digest_size=32).hexdigest()
    new_account_data(path, user, (current_balance - amount), key)

    path = "accounts/recived" + blake2b(reciver.encode(), digest_size=32).hexdigest()
    if exists(path):
        with open(path, "a") as file:
            file.writelines(f"{amount}\n")
    else:
        with open(path, "w") as file:
            file.writelines(f"{amount}\n")

    return (current_balance - amount)

def withdraw(user, amount, current_balance):
    if amount > current_balance:
        print("Lack of sufficient funds in the account")
        return False

    password = "Error - wrong password"
    with open("passwords/passwords.csv", "r") as login_stor:
        user_hashed = blake2b(user.encode()).hexdigest()
        for line in login_stor:
            if user_hashed == line.split(",")[0]:
                for attempt in range(0,3):
                    password = input()
                    password = maskpass.askpass(prompt="Repeat your password: ", mask="*")
                    password_hashed = blake2b(password.encode()).hexdigest()
                    if password_hashed == line.split(",")[1].strip("\n"):
                        print("password correct")
                        break 
                    elif attempt == 2:
                        print("Too many wrong attemps")
                        return False
                    else:
                        print("Incorrect password!")
                break
    
    key = gen_key(user, password)
    path = "accounts/" + blake2b(user.encode(), digest_size=32).hexdigest()
    new_account_data(path, user, (current_balance - amount), key)
    return (current_balance - amount)

def deposit_cash(user, amount, current_balance):
    password = "Error - wrong password"
    with open("passwords/passwords.csv", "r") as login_stor:
        user_hashed = blake2b(user.encode()).hexdigest()
        for line in login_stor:
            if user_hashed == line.split(",")[0]:
                for attempt in range(0,3):
                    password = input()
                    password = maskpass.askpass(prompt="Repeat your password: ", mask="*")
                    password_hashed = blake2b(password.encode()).hexdigest()
                    if password_hashed == line.split(",")[1].strip("\n"):
                        print("password correct")
                        break 
                    elif attempt == 2:
                        print("Too many wrong attemps")
                        return False
                    else:
                        print("Incorrect password!")
                break
    
    key = gen_key(user, password)
    path = "accounts/" + blake2b(user.encode(), digest_size=32).hexdigest()
    new_account_data(path, user, (current_balance + amount), key)

    return (current_balance + amount)

def main():
    while True:
        while True:
            print("What you would like to do?")
            print("[1] Sign up")
            print("[2] Sign in")
            print("[3] Exit")
            choice = input()
            match choice:
                case "1":
                    deposit = input("What is first deposit? ")
                    sign_up(deposit)
                case "2":
                    name, balance = sign_in()
                    break
                case "3":
                    sys.exit()
                case _:
                    print("Wrong input")
        while True:
            print(f"Hello {name}, your balance is {balance}")
            print("What you would like to do?")
            print("[1] Deposit money")
            print("[2] Withdraw money")
            print("[3] Transfer money")
            print("[4] Log out")
            print("[5] Log out and quit")
            choice = input()
            match choice:
                case "1":
                    amount = int(input("How much would you like to deposit? "))
                    print(deposit_cash(name, amount, balance))
                case "2":
                    amount = int(input("How much would you like to withdraw? "))
                    print(withdraw(name, amount, balance))
                case "3":
                    amount = input("How much would you like to transfer? ")
                    reciver = input("To who? ")
                    print(transfer(name, amount, reciver, balance))
                case "4":
                    del name
                    del balance
                    del choice
                    break
                case "5":
                    sys.exit()
                case _:
                    print("Wrong input")

if __name__ == "__main__":
    main()