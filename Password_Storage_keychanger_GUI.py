from tkinter import *
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
import hashlib

password_dict = {}
# Can add password file directory (with file name) to this string for quicker access after setup is complete
fname = "/Users/Scott/PycharmProjects/Password_Encryptor/Passwords_Encrypted.txt"
key_input =''

def make_form(root, field, website = ''):
    entry = []
    count = 0
    site = StringVar()
    site.set(website)
    for i in field:
        Label(root, text=i).grid(row=count, column=0)
        if count > 0:
            if website != '':
                ent = Entry(root, textvariable=site)
            else:
                ent = Entry(root)
            ent.grid(row=count, column=1)
            entry.append(ent)
            if count == 1:
                ent.focus()

        count +=1
    return entry

class get_GUI:
    def __init__(self):
        self.__mainWindow = Tk()
        self.ff = StringVar()
        self.ff.set(value=fname)
        self.labelText = 'Enter Key Phrase'
        self.Label = Label(self.__mainWindow, text=self.labelText)
        self.KeyEntry = Entry(self.__mainWindow, width=40)
        self.FileLabel =Label(self.__mainWindow, text='Enter password file location')
        self.FileEntry = Entry(self.__mainWindow, width=40, textvariable=(self.ff))
        self.depositButton = Button(self.__mainWindow, text='OK', command=self.login, width=10)
        self.quitButton = Button(self.__mainWindow, text='Quit', command=self.quitter, width=10)
        self.Label.pack()
        self.KeyEntry.pack()
        self.KeyEntry.focus()
        self.FileLabel.pack()
        self.FileEntry.pack()
        self.file_name = self.FileEntry
        self.__mainWindow.bind('<Return>', self.login)
        self.depositButton.pack()
        self.quitButton.pack()

        mainloop()

    def login(self, event=None):
        # try:
        global key_input
        global key
        global fname
        key = self.KeyEntry.get()
        key_input = hashlib.sha256(self.KeyEntry.get().encode()).digest()
        f = open(self.FileEntry.get(), 'rb')
        fname = self.FileEntry.get()
        F = f.read()
        f.close()
        # Using key decrypt the file
        # F = F[32:]
        print(F)
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
        open2 = GUI_2(self.__mainWindow)
        #except:
         #  self.confirm = tk.messagebox.askokcancel('Error',
          #                                          'Incorrect key phrase, please try again')

    def quitter(self):
        self.__mainWindow.destroy()

class GUI_2:
    def __init__(self, root):
        self.__mainWindow = Toplevel(root)
        self.__mainWindow.protocol("WM_DELETE_WINDOW", (lambda: self.quitter(root)))
        self.wide = 30
        self.L1 = Label(self.__mainWindow, text="Select Action:")
        self.b0 = Button(self.__mainWindow, text='Quit', command=(lambda: self.quitter(root)), width=self.wide)
        self.b1 = Button(self.__mainWindow, text="Get login credentials",
                         command=(lambda: self.get_login()), width=self.wide)
        self.b2 = Button(self.__mainWindow, text="Add login credentials to database",
                         command=(lambda: self.add_login()), width=self.wide)
        self.b3 = Button(self.__mainWindow, text="Remove login credentials from database",
                         command=(lambda: self.del_login()), width=self.wide)
        self.b4 = Button(self.__mainWindow, text="Show stored websites",
                         command=(lambda: self.show_login()), width=self.wide)
        self.b5 = Button(self.__mainWindow, text="Change encryption key",
                         command=(lambda: self.change_key()), width=self.wide)
        self.L1.grid(row=0, column=0)
        self.b0.grid(row=100, column=0)
        self.b1.grid(row=1, column=0)
        self.b2.grid(row=2, column=0)
        self.b3.grid(row=3, column=0)
        self.b4.grid(row=4, column=0)
        self.b5.grid(row=5, column=0)

        mainloop()

    def get_login(self):
        login = login_GUI(self.__mainWindow)

    def add_login(self):
        add = add_GUI()

    def del_login(self):
        delete = del_GUI()

    def show_login(self):
        show = show_GUI(self.__mainWindow)

    def change_key(self):
        change = change_key(self.__mainWindow)

    def quitter(self, root):
        self.save_encrypt()
        self.__mainWindow.destroy()
        root.destroy()


    def pad(self, text):
        # Function to ensure string to encrypt is correct length
        # AES encryption requires bytestring length of a multiple of 16 bytes
        while len(text) % 16 != 0:
            text += ' '
        return text

    def save_encrypt(self):
        # Function to combine dictionary into single string, and save over file
        # Calls 'pad' function to ensure string is correct length
        # Adds SHA256 encrypted key bytestring to beginning of file for key validation when next opened
        global key_input
        global fname
        g = open(fname, 'wb')
        aes = AES.new(key_input, AES.MODE_ECB)
        text = 'website username password\n'
        for i in password_dict:
            string1 = str(i) + ' ' + str(password_dict[i][0]) + ' ' + str(password_dict[i][1]) + '\n'
            text = text + string1
        padded_text = self.pad(text)
        padded_text = padded_text.encode()
        text_to_write = aes.encrypt(padded_text)
        g.write(text_to_write)
        g.close()

class login_GUI:
    def __init__(self, root, website=''):
        self.text = ['Enter credentials to retrieve:', 'Website']

        self.__3Window = Toplevel(root)
        self.username = StringVar()
        self.password = StringVar()
        self.entry = make_form(self.__3Window, self.text, website=website)

        if website != '':
            self.retrieve_password(entry=self.entry)

        self.b1 = Button(self.__3Window, text='OK', command=(lambda: self.retrieve_password(entry=self.entry)))
        self.b2 = Button(self.__3Window, text='Quit', command=self.__3Window.destroy)
        # self.bind('<Return>', (lambda event, e=self.entry: self.retrieve_password(e, password, username)))
        self.user = Label(self.__3Window, text='Username').grid(row=4, column=0)
        self.user_ent = Entry(self.__3Window, textvariable=(self.username)).grid(row=4, column=1)
        self.pw = Label(self.__3Window, text='Password').grid(row=5, column=0)
        self.ent = Entry(self.__3Window, textvariable=(self.password)).grid(row=5, column=1)
        # self.__3Window.bind('<Return>', self.retrieve_password(entry=self.entry))
        self.b1.grid(row=100, column=0)
        self.b2.grid(row=100, column=1)

        mainloop()

    def retrieve_password(self, entry, event=None):
        # Function to access dictionary entries and display to user
        name = entry[0].get()
        name = name.replace(" ", "_")
        try:
            login = password_dict[name]
            self.username.set(login[0])
            self.password.set(login[1])
        except:
            self.username.set('')
            self.password.set('')
            self.error_msg = tk.messagebox.askokcancel('Error', 'Login credentials for "{}" do not exist'.format(name))

class add_GUI:
    def __init__(self):
        self.text = ['Enter credentials to add:', 'Website', 'Username', 'Password']
        self.__3Window = tk.Tk()
        error = StringVar()

        self.entry = make_form(self.__3Window, self.text)
        self.b1 = Button(self.__3Window, text='OK',
                         command=(lambda e=self.entry: self.add_login(e, error)))
        self.b2 = Button(self.__3Window, text='Quit', command=self.__3Window.destroy)
        # self.bind('<Return>', (lambda event, e=self.entry: self.retrieve_password(e, password, username)))
        self.error_label = Label(self.__3Window, text='')
        self.b1.grid(row=100, column=0)
        self.b2.grid(row=100, column=1)
        self.error_label.grid(row=10, column=0)

    def add_login(self, entry, error):
        # Function to add new data to dictionary
        login = entry[0].get()
        login = login.replace(" ", "_")
        if login == "" or entry[1].get() == "" or entry[2].get() == "":
            self.error_msg = tk.messagebox.askokcancel('Error', 'Invalid login credentials, please try again')
            return 0
        credentials = [entry[1].get(), entry[2].get()]
        if login in password_dict:
            d = self.select_menu(entry[0].get())
            if d == False:
                return 0
        password_dict[login] = credentials
        self.confirm = tk.messagebox.askokcancel('Confirmation', 'Login credentials for {} added to database'.format(login))
        print("Login credentials added to database")
        self.__3Window.destroy()

    def select_menu(self, login):
        msgBox = tk.messagebox.askquestion('Error', 'Login credentials for {} already exist, would you like to replace?'.format(login))
        if msgBox == "yes":
            return True
        else:
            return False

class del_GUI:
    def __init__(self):
        self.text = ['Enter credentials to Remove:', 'Website']
        self.__3Window = tk.Tk()
        error = StringVar()

        self.entry = make_form(self.__3Window, self.text)
        self.b1 = Button(self.__3Window, text='OK',
                         command=(lambda e=self.entry: self.del_login(e)))
        self.b2 = Button(self.__3Window, text='Quit', command=self.__3Window.destroy)
        # self.bind('<Return>', (lambda event, e=self.entry: self.retrieve_password(e, password, username)))
        self.error_label = Label(self.__3Window, text='')
        self.b1.grid(row=100, column=0)
        self.b2.grid(row=100, column=1)
        self.error_label.grid(row=10, column=0)

    def del_login(self, entry):
        # Delete entries from dictionary by name
        login = entry[0].get()
        login = login.replace(" ", "_")
        if login == "":
            self.error_label['text'] = 'Error: Login credentials not in database'
            return 0
        if login in password_dict:
            msgBox = tk.messagebox.askquestion('Confirmation',
                                               'Are you sure you want to remove the entry for {}, this action cannot be undone'.format(
                                                   login))
            if msgBox == "yes":
                del password_dict[login]
                tk.messagebox.askokcancel('Complete', '{} has been removed from the database'.format(login))
                self.__3Window.destroy()
        else:
            tk.messagebox.askokcancel('Complete', 'No change has been made to the database'.format(login))
            self.__3Window.destroy()

class show_GUI:
    def __init__(self, root):
        self.__showWindow = Toplevel(root)
        Label(self.__showWindow, text='Select username to show login credentials').grid(row=0)
        self.a = 1
        self.button_dict = {}
        for cred in password_dict:
            action = lambda x = cred: self.get_cred(x)
            self.button_dict[cred] = Button(self.__showWindow, text=cred, width=30,
                                           command=action).grid(row=self.a)
            self.a+=1

        Button(self.__showWindow, text='Quit', width=30, command=self.__showWindow.destroy).grid(row=self.a)

        mainloop()

    def get_cred(self, cred):
        login2 = login_GUI(self.__showWindow, cred)

class change_key:
    def __init__(self, root):
        self.__change_key = Toplevel(root)
        self.entries = []
        text1 = ['Change key Phrase', 'Enter current key', 'Enter new key', 'Confirm new key']
        self.password = make_form(self.__change_key, text1)
        self.b1 = Button(self.__change_key, text='OK',
                         command=(lambda : self.change(self.password)))
        self.b2 = Button(self.__change_key, text='Quit', command=self.__change_key.destroy)
        self.b1.grid(row=100, column=0)
        self.b2.grid(row=100, column=1)

    def change(self, entries):
        global key
        global key_input
        if entries[0].get() == key:
            if entries[1].get() == entries[2].get():
                key = entries[1].get()
                key_input = hashlib.sha256(key.encode()).digest()
                self.__change_key.destroy()
                self.confirm = tk.messagebox.askokcancel('Confirmation', "Key phrase has been changed to '{}' \n"
                                                                         "Store this in a safe place as it is not recoverable"
                                                         .format(key))
            else:
                self.error = tk.messagebox.askokcancel('Error', 'New key phrases do not match, please try again')
        else:
            self.error = tk.messagebox.askokcancel('Error', 'Current key is incorrect, please try again')

if __name__ == "__main__":
    # open file and decrypt data
    my_GUI = get_GUI()
