# Password Manager

A simple, yet effective password manager built with Python and Tkinter. I built it for myself out of distrust in third-party password managers. Encryption key is derived from the master password and can either be stored on device or not.

## Overview
**Secure Password Storage**
- Store service name, passwords, username, email and notes securely for each account.
- Organize stored passwords by category.
- Sort, filter, and search through stored passwords.
- Quickly copy passwords to the clipboard.
**Security**
- Access your vault with a single master password.
- Secure storage using Fernet encryption.
- Passwords are encrypted using an encryption key derived from the master password (using PBKDF2HMAC).
- Choose whether the encryption key is stored on your device:
  - *Stored:* Less secure, but allows for manual decryption if you forget the master password.
  - *Not stored:* More secure, but you will lose all your data if you lose your the master password.


## Installation and usage
1. Ensure Python 3.x and pip are installed on your system.
2. Clone this repository or download the source code.
   ```sh
   git clone https://github.com/lanlebar/password_manager.git
   cd password_manager
   ```
3. Install packages
   ```sh
   pip install -r requirements.txt
   ```
4. Run main.py
   ```sh
   python3 main.py
   ```
5. Optionally set the backup path(s) - `backup_dir_paths` array in `settings.json`
## Dependencies
- `tkinter` for the GUI.
- `cryptography` for encryption and decryption.
- `Levenshtein` for the search algorithm


## Keyboard shortcuts
   - `Ctrl + N`: Add new password
   - `Ctrl + F`: Search
   - `<number>`: Set focus on corresponding password

## Gallery
<p align="center">
  <img src="images/app.png" alt="App screen">
</p>
<p align="center">
  <img src="images/manage.png" alt="App screen">
</p>
<p align="center">
  <img src="images/login.png" alt="Login screen">
</p>
<p align="center">
  <img src="images/signup.png" alt="Sign up screen">
</p>
