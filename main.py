import configparser
import getpass
import os
import sys
import json
import time
import hashlib
import hmac

from functions import check_password_policy
from functions import hash_string
from functions import encrypt
from functions import decrypt

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

    os.system("clear")

    print("You need to provide a master password to continue\n")
    print("Password policy:")
    print(f"[*] Should be at least {length} characters")
    print(f"[*] Should contain at least {numbers} numbers")
    print(f"[*] Should contain at least {specialchars} special characters within ( ! @ # $ % & )")
    print(f"[*] Should contain at least {uppercase} uppercase letters\n")
    
    # Checking if the password meets the requirements of the password policy
    matched_passwords = False
    while not matched_passwords:
        strong_password = False
        while not strong_password:
            master_password = getpass.getpass(prompt = "Please Enter your password --> ")

            if(check_password_policy(master_password, length, numbers, specialchars, uppercase)):
                strong_password = True
            else:
                print("[-] The entered password does not meet the password policy requirements.")
                print("Please try again.")

        master_password_confirm = getpass.getpass(prompt = "Please Confirm your password --> ")
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
    key = f.readline().strip()
    f.close()

    if(key == hashed_master_password):
        choice = 0
        while(str(choice) in "012345"):
            os.system("clear")
            print("Welcome back to your password manager!")
            print("Please select an option")
            print("[1] - Create a new password entry")
            print("[2] - Edit a password entry")
            print("[3] - Delete a password entry")
            print("[4] - Search for an entry")
            print("[5] - Display all the entries")
            print("[6] - Exit")
            choice = int(input("--> "))

            if(choice == 1):
                os.system("clear")
                additional_attributes = []
                print("The entry that will be created will contain the following: ")
                print("- Account name")
                print("- Username")
                print("- Password")
                
                valid_answer = False
                while not valid_answer:
                    answer = input("Do you want to add other attributes? [y/n] --> ")
                    if(answer != "y" and answer != "n"):
                        print("Invalid choice, try again")
                    else:
                        valid_answer = True

                while answer != "n":
                    attribute = input("Enter the name of the attribute --> ")
                    additional_attributes.append(attribute)
                    answer = input("Do you want to add other attributes? [y/n] --> ")

                account_name = input("Account name: ")
                username = input("Username: ")
                password = getpass.getpass(prompt = "Password: ")

                dictionary = {
                    "Account name": account_name,
                    "Username": username,
                    "password": password
                }
                
                if(additional_attributes != []):
                    for attribute in additional_attributes:
                        attribute_value = input(f"{attribute}: ")
                        dictionary[attribute] = attribute_value

                # Converting the dictionary into json string
                json_string = json.dumps(dictionary, indent=4)
                print(json_string)

                # Encrypting the json string with the key
                enc_json_string = encrypt(json_string, key)
                print(enc_json_string)

                # Writing the encrypted json string into the .password file
                with open("./.passwords", "a") as pass_file:
                    pass_file.write(enc_json_string + '\n')

            elif(choice == 2):
                os.system("clear")

            elif(choice == 3):
                os.system("clear")

            elif(choice == 4):
                os.system("clear")
            elif(choice == 5):
                os.system("clear")
                print("Here are all the saved entries:")
                
                # Retrieving the encrypted data from .passwords file
                entries = []
                with open("./.passwords", "r") as pass_file:
                    entries = pass_file.readlines()
                
                for entry in entries:
                    dec_entry = decrypt(entry.strip(), key)
                    print(dec_entry)
                time.sleep(10)
            else:
                print("Goodbye")
                sys.exit()
        else:
            print("Wrong password, Goodbye!")
            sys.exit()




