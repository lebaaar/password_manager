import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

def derive_fernet_key_from_password(plain_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"<your-salt-here>",
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(plain_password.encode()))

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

def main():
    input_password = input("Enter the master password: ")
    key = derive_fernet_key_from_password(input_password)
    encrypted_content = input("Enter the encrypted content: ")

    decrypted_message = decrypt_content(encrypted_content.encode(), key)
    if decrypted_message:
        print(f"Decrypted message:\n{decrypted_message}")

if __name__ == '__main__':
    main()