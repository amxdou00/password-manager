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
from functions import display_entries

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
            print("[4] - Search by account name")
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
                entry_number = int(input("Please enter the entry number --> "))

                # Appending new entry at the end of the file
                with open("./.passwords", "r+") as pass_file:
                    lines = pass_file.readlines()

                line_number = 1
                dec_entry_dict = {}
                for line in lines:
                    if entry_number == line_number:
                        dec_entry = decrypt(line.strip(), key)
                        dec_entry_dict = json.loads(dec_entry)
                        for dict_key in dec_entry_dict.keys():
                            if(dict_key == "password"):
                                dec_entry_dict[dict_key] = getpass.getpass(prompt = f"{dict_key}: ")
                            else:
                                dec_entry_dict[dict_key] = input(f"{dict_key}: ")
                        break
                    else:
                        line_number += 1
                        continue

                # Converting the dictionary into json string
                json_string = json.dumps(dec_entry_dict, indent=4)

                # Encrypting the json string with the key
                enc_json_string = encrypt(json_string, key)

                # Writing the encrypted json string into the .password file
                with open("./.passwords", "a") as pass_file:
                    pass_file.write(enc_json_string + '\n')

                time.sleep(3)

                # Deleting the old entry
                with open("./.passwords", "r") as pass_file:
                    lines = pass_file.readlines()
                lines[entry_number-1] = ""
                with open("./.passwords", "w") as pass_file:
                    pass_file.writelines(lines)

                time.sleep(5)

            elif(choice == 3):
                os.system("clear")
                entry_number = int(input("Please enter the entry number --> "))
                with open("./.passwords", "r") as pass_file:
                    lines = pass_file.readlines()
                lines[entry_number-1] = ""
                with open("./.passwords", "w") as pass_file:
                    pass_file.writelines(lines)

                print("[+] The entry has been deleted")
                time.sleep(5)

            elif(choice == 4):
                os.system("clear")

            elif(choice == 5):
                os.system("clear")
                print("Here are all the saved entries:")
                display_entries(key)
                time.sleep(5)

            else:
                print("Goodbye")
                sys.exit()
    else:
        print("Wrong password, Goodbye!")
        sys.exit()




