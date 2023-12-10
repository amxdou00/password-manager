import hashlib

def check_password_policy(password, length, numbers, specialchars, uppercase):
    length_check = False
    numbers_check = False
    specialchars_check = False
    uppercase_check = False

    # Checking the length
    if(len(password) >= length):
        length_check = True

    # Checking the numbers, special characters and uppercase letters
    numbers_count = 0
    specialchars_count = 0
    uppercase_count = 0

    for char in password:
        if char.isdigit():
            numbers_count += 1
        if char in "!@#$%&":
            specialchars_count += 1
        if char.isupper():
            uppercase_count +=1

    if(numbers_count >= numbers):
        numbers_check = True
    if(specialchars_count >= specialchars):
        specialchars_check = True
    if(uppercase_count >= uppercase):
        uppercase_check = True

    # Checking if the password policy is met
    if(length_check and numbers_check and specialchars_check and uppercase_check):
        return True
    else:
        return False

def hash_string(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    hashed_string = sha256_hash.hexdigest()
    return hashed_string

# This function encrypts a string based on a given key
def encrypt(string, key):

	# Converting the string into an array
	string_list = list(string)

	# For each character of the key, we add its ASCII value to each character of the string
	for key_unit in list(key):
		for j in range(0, len(string_list)):
			string_list[j] = chr( ord(string_list[j]) + ord(key_unit) )

	return "".join(string_list)

# This function decrypts a string based on a given key
def decrypt(string, key):

	# Converting the string and the key into an array
	string_list = list(string)
	key_list = list(key)

	# For each character of the key, we substract its ASCII value to each character of the string
	for key_unit in key_list:
		for j in range(0, len(string_list)):
			string_list[j] = chr( ord(string_list[j]) - ord(key_unit) )


	return "".join(string_list)