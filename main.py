import configparser
import getpass
import os
import sys

from functions import check_password_policy
from functions import hash_string

if (os.path.getsize("./.key")==0):
    # Reading config file
    config_obj = configparser.ConfigParser()
    config_obj.read("./config.ini")
    password_policy = config_obj["password_policy"]

    # Importing variables
    length = int(password_policy["length"])
    numbers = int(password_policy["numbers"])
    specialchars = int(password_policy["specialchars"])
    uppercase = int(password_policy["uppercase"])

    print("You need to provide a master password to continue\n")
    print("Password policy:")
    print(f"[*] Should be at least {length} characters")
    print(f"[*] Should contain at least {numbers} numbers")
    print(f"[*] Should contain at least {specialchars} special characters within ( ! @ # $ % & )")
    print(f"[*] Should contain at least {uppercase} uppercase letters")
    
    matched_passwords = False
    while not matched_passwords:
        strong_password = False
        while not strong_password:
            master_password = getpass.getpass(prompt = "[*] Please Enter your password --> ")

            if(check_password_policy(master_password, length, numbers, specialchars, uppercase)):
                strong_password = True
            else:
                print("[-] The entered password does not meet the password policy requirements.")
                print("Please try again.")

        master_password_confirm = getpass.getpass(prompt = "[*] Please Confirm your password --> ")
        if(master_password == master_password_confirm):
            matched_passwords = True
        else:
            print("[-] The two passwords do not match!")
            print("Please try again.")

    # Hashing the master password and writing it to the .key file
    hashed_master_password = hash_string(master_password)
    f = open("./.key", "w")
    f.write(hashed_master_password)
    f.close()
    print("[+] You've successfully created your password!")
    sys.exit()
else:
    print("Please enter your master password to continue")
    master_password = getpass.getpass(prompt = "--> ")
    hashed_master_password = hash_string(master_password)
    f = open("./.key", "r")
    key = f.readline()
    if(key == hashed_master_password):
        print("Correct password")
    else:
        print("Wrong password")




