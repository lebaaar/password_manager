from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

SECRET_KEY_FILE = f"{os.path.dirname(__file__)}/secret.key"
ENCRYPTED_KNOWN_VALUE_FILE = f"{os.path.dirname(__file__)}/known_value.bin"
KNOWN_VALUE_B = "This is a known value."

def derive_fernet_key_from_password(plain_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(plain_password.encode()))

# Save, get, remove secret key
def save_key_to_file(key):
    with open(SECRET_KEY_FILE, "wb") as f:
        f.write(key)

def load_key_from_file():
    with open(SECRET_KEY_FILE, "rb") as f:
        key = f.read()
    return key

def remove_key_file():
    if os.path.exists(SECRET_KEY_FILE):
        os.remove(SECRET_KEY_FILE)

# Save or get encrypted known value
def save_known_value(key):
    f = Fernet(key)
    encrypted_known_value = f.encrypt(KNOWN_VALUE_B.encode())
    with open(ENCRYPTED_KNOWN_VALUE_FILE, "wb") as f:
        f.write(encrypted_known_value)

def remove_known_value():
    if os.path.exists(ENCRYPTED_KNOWN_VALUE_FILE):
        os.remove(ENCRYPTED_KNOWN_VALUE_FILE)

# Verify password
def verify_password_with_stored_key(plain_password):
    if not os.path.exists(SECRET_KEY_FILE) or not os.path.isfile(SECRET_KEY_FILE) or os.path.getsize(SECRET_KEY_FILE) == 0:
        raise FileNotFoundError(f"{SECRET_KEY_FILE} not found. Please set up a master password first.")
    with open(SECRET_KEY_FILE, "rb") as f:
        stored_key = f.read()
    entered_key = base64.urlsafe_b64encode(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        iterations=100000,
        backend=default_backend()
    ).derive(plain_password.encode()))
    return entered_key == stored_key

def verify_password_without_stored_key(plain_password):
    if not os.path.exists(ENCRYPTED_KNOWN_VALUE_FILE) or not os.path.isfile(ENCRYPTED_KNOWN_VALUE_FILE) or os.path.getsize(ENCRYPTED_KNOWN_VALUE_FILE) == 0:
        raise FileNotFoundError(f"{ENCRYPTED_KNOWN_VALUE_FILE} not found. Please set up a master password first.")

    with open(ENCRYPTED_KNOWN_VALUE_FILE, "rb") as f:
        encrypted_known_value = f.read()

    key = derive_fernet_key_from_password(plain_password)
    f = Fernet(key)
    try:
        decrypted_known_value = f.decrypt(encrypted_known_value).decode()
        return decrypted_known_value == KNOWN_VALUE_B
    except InvalidToken:
        return False

# Set up master password
def setup_master_password(master_password, save_key, delete_other_files=True):
    if save_key:
        key = derive_fernet_key_from_password(master_password)
        save_key_to_file(key)
        if delete_other_files:
            if os.path.exists(ENCRYPTED_KNOWN_VALUE_FILE):
                os.remove(ENCRYPTED_KNOWN_VALUE_FILE)
        return key
    else:
        # Encrypt the known value with the password
        key = derive_fernet_key_from_password(master_password)
        save_known_value(key)
        if delete_other_files:
            if os.path.exists(SECRET_KEY_FILE):
                os.remove(SECRET_KEY_FILE)
        return key

# Encryption and decryption of contnet
def encrypt_content(plain_content, key):
    if not isinstance(plain_content, str):
        raise ValueError("Content to be encrypted must be a string.")
    try:
        f = Fernet(key)
        encrypted_message = f.encrypt(plain_content.encode())
        return encrypted_message
    except Exception as e:
        print(f"Encryption failed with error: {e}")

def decrypt_content(encrypted_content, key):
    try:
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_content)
        return decrypted_message.decode()
    except InvalidToken:
        print("Decryption failed: Invalid token. The key may be incorrect or the data may be corrupted.")
        return None
    except Exception as e:
        print(f"Decryption failed with error: {e}")
        return None