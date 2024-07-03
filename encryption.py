from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import bcrypt
import base64

SECRET_KEY_FILE = 'secret.key'
SALT_FILE = 'salt.bin'

def generate_or_load_salt():
    try:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    except FileNotFoundError:
        salt = bcrypt.gensalt()
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    return salt

def derive_fernet_key_from_password(plain_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=generate_or_load_salt(),
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(plain_password.encode()))

def save_key_to_file(key):
    with open(SECRET_KEY_FILE, 'wb') as f:
        f.write(key)

def load_key_from_file():
    with open(SECRET_KEY_FILE, 'rb') as f:
        key = f.read()
    return key

def verify_password(plain_password):
    with open(SECRET_KEY_FILE, 'rb') as f:
        stored_key = f.read()
    entered_key = base64.urlsafe_b64encode(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=generate_or_load_salt(),
        iterations=100000,
        backend=default_backend()
    ).derive(plain_password.encode()))
    return entered_key == stored_key


def setup_master_password(master_password):
    key = derive_fernet_key_from_password(master_password)
    save_key_to_file(key)
    return key

def encrypt_content(plain_content, key):
    if type(plain_content) != str:
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
