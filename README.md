# Password-Manager
Store passwords in an encrypted file.  Can be accessed with key phrase only.

password_setup.py must be run first to create original encrypted file.
  - Do not delete the sample login credentials without adding credentials of your own
  
GUI manager that allows quick access to any number of passwords.
File that stores passwords is encrypted using AES encryption with a key phrase that is
hashed to a bytestring using SHA256. Key is not stored with file and is NOT recoverable unless brute-forced

Simple procedure to add and remove passwords to database

To speed up usage, file location can be entered into fname variable for autofill

Future improvement:
Alphabetize password entries
