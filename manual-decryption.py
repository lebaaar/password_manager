try:
    import encryption as enc
except ImportError:
    print("encryption.py not found. Please make sure encryption.py is in the same directory as manual-decryption.py")

def main():
    input_password = input("Enter the master password: ")
    key = enc.derive_fernet_key_from_password(input_password)
    encrypted_content = input("Enter the encrypted content: ")

    decrypted_message = enc.decrypt_content(encrypted_content.encode(), key)
    if decrypted_message:
        print(f"Decrypted message:\n{decrypted_message}")

if __name__ == '__main__':
    main()