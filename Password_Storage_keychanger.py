# Password Storage
# Program reads from encrypted file using SHA256 encrypted key to generate 32 byte password
# 1. Retrieve login credentials from encrypted data
# 2. Add new login credentials to be encrypted when program is exited - Also used to update out of date
#    passwords
# 3. Remove login credentials specified by organization name
# 4. Show a list of all of the stored organizations
# 5. Exits and saves all changes made to the file - program must be exited using this function in order
#    for changes to be saved to encrypted file
# 0. Change encryption key - Key is stored in encrypted file at every save and exit to be compared to
#    user input key (hashed by SHA256) on next startup

# Data is not decrypted until correct key is input
# All spaces in website/organization names are converted to "_" before saving
# Upon retrieval input spaces are converted to "_" no need to type with "_"
# Typing with underscore is OK as well
# ex. "Bank_of_America" == "Bank_of_America"

from Crypto.Cipher import AES
import hashlib

password_dict = {}

def change_key():
    # Function to change encryption key
    global key_input
    key_old = input("Enter current key: ")
    if hashlib.sha256(key_old.encode()).digest() == key_input:
        key_new = input("Enter new key: ")
        print("Write new key down so that you do not forget it.")
        print("Key changed to {}".format(key_new))
        key_input = hashlib.sha256(key_new.encode()).digest()
        print("key_input: {}".format(key_input))

def retrieve_password(name):
    # Function to access dictionary entries and display to user
    name = name.replace(" ", "_")
    try:
        login = password_dict[name]
        return "\nUsername: {}\nPassword: {}\n".format(login[0], login[1])
    except:
        return "\nLogin Credentials do not exist\n"

def add_info():
    # Function to add new data to dictionary
    print("Enter new login credentials")
    login = input("Enter website: ")
    login = login.replace(" ", "_")
    if login == "":
        return 0
    username = input("Enter username: ")
    password = input("Enter password: ")
    credentials = [username, password]
    if login in password_dict:
        d = input("Login credentials for {} already exist, would you like to replace? (y/n)".format(login))
        if d == "n":
            return 0
    password_dict[login] = credentials
    print("Login credentials added to database")

def del_info():
    # Delete entries from dictionary by name
    login = input("Enter website credentials to delete: ")
    login = login.replace(" ", "_")
    if login in password_dict:
        check = input("Are you sure you want to remove this entry, this action cannot be undone(y/n): ")
        if check == "y":
            del password_dict[login]
            print("{} removed from password list".format(login))
    else:
        print("Error: Login credentials not stored for that website.")

def get_key(fname):
    # Initialization function
    # Open encrypted passwords file as byte file and create dictionary
    f = open(fname, 'rb')
    F = f.read()
    f.close()
    key = F[:31]
    print("key: {}".format(key))

def open_file(fname):
    # Function to open encrypted file, decrypt using user-set key, and populate dictionary
    f = open(fname, 'rb')
    F = f.read()
    f.close()
    # Using key decrypt the file
    # F = F[32:]
    aes = AES.new(key_input, AES.MODE_ECB)
    F = aes.decrypt(F)
    # Process data so that it is in correct format
    string1 = str(F)
    string1 = string1[2:-1]
    G = string1.split("\\")
    G = G[:-1]
    count = 0
    G = G[1:]
    for i in G:
        G[count] = i[1:]
        count += 1
    # Create dict to read from
    for i in range(0, len(G)):
        list1 = G[i].split()
        password_dict[list1[0]] = [list1[1], list1[2]]

def pad(text):
    # Function to ensure string to encrypt is correct length
    # AES encryption requires bytestring length of a multiple of 16 bytes
    while len(text) % 16 != 0:
        text += ' '
    return text

def save_encrypt(fname):
    # Function to combine dictionary into single string, and save over file
    # Calls 'pad' function to ensure string is correct length
    # Adds SHA256 encrypted key bytestring to beginning of file for key validation when next opened
    global key_input
    g = open(fname, 'wb')
    aes = AES.new(key_input, AES.MODE_ECB)
    text = 'website username password\n'
    for i in password_dict:
        string1 = str(i) + ' ' + str(password_dict[i][0]) + ' ' + str(password_dict[i][1]) + '\n'
        text = text + string1
    padded_text = pad(text)
    padded_text = padded_text.encode()
    text_to_write = aes.encrypt(padded_text)
    g.write(text_to_write)
    g.close()

def show_info():
    # Function to show all entries in database
    for i in password_dict.keys():
        print(i)

def main():
    # Create menu - should add to a menu() function
    print("Select action: ")
    print("1. Get login credentials")
    print("2. Add login credentials to database")
    print("3. Remove login credentials in database")
    print("4. Show stored websites")
    print("5. Exit program")
    print("0. Change encryption key")
    X = input()

    if X == "5":
        # Encrypt file an save to disk
        save_encrypt(fname)
        exit()
    if X == "1":
        get_login = input("Enter credentials to retrieve: ")
        print(retrieve_password(get_login))
        z = input("Press Enter to continue...")
    if X == "2":
        add_info()
        z = input("Press Enter to continue...")
    if X == "3":
        del_info()
    if X == "4":
        show_info()
        z = input("Press Enter to continue...")
    if X == "0":
        change_key()
    # For debug only
    if X == "9":
        print(password_dict)
        print(key_input)

if __name__ == "__main__":
    # open file and decrypt data
    fname = "/Users/Scott/PycharmProjects/Password_Encryptor/Passwords_encrypted.txt"
    get_key(fname)
    key_input = input("Enter key: ")
    key_input = hashlib.sha256(key_input.encode()).digest()
    try:
        open_file(fname)
    except:
        print('Error: Incorrect keycode')
        exit()
    # if key_input == key:
    while True:
        main()




