# Create blank encrypted password file

from tkinter import *
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
import hashlib

# GUI to enter name of file and key phrase


password_dict = {}
password_dict['sample'] = ['Username', 'password']

def pad(text):
    # Function to ensure string to encrypt is correct length
    # AES encryption requires bytestring length of a multiple of 16 bytes
    while len(text) % 16 != 0:
        text += ' '
    return text

def save_encrypt(fname, key_input):
    # Function to combine dictionary into single string, and save over file
    # Calls 'pad' function to ensure string is correct length
    # Adds SHA256 encrypted key bytestring to beginning of file for key validation when next opened
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

# create blank file with headers only

if __name__ == "__main__":
    # open file and decrypt data

    __mainWindow = Tk()
    Label(__mainWindow, text='Enter name of password file: ').pack()
    name = Entry(__mainWindow, textvariable=StringVar(value='Passwords_Encrypted.txt'))
    name.pack()
    Label(__mainWindow, text='Enter key phrase:').pack()
    key = Entry(__mainWindow, textvariable=StringVar(value='password'))
    key.pack()


    def create_file():
        print(key.get())
        key_input = hashlib.sha256(key.get().encode()).digest()
        save_encrypt(name.get(), key_input)


    b1 = Button(__mainWindow, text='OK',
                     command=create_file).pack()
    b2 = Button(__mainWindow, text='Quit', command=__mainWindow.destroy).pack()

    mainloop()