import tkinter as tk
from tkinter import simpledialog, messagebox
import encryption as enc
import os


class EncryptionError(Exception):
    pass

class DecryptionError(Exception):
    pass

class LoginError(Exception):
    pass


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.key = None
        self.show_initial_screen()

    def check_key_presence(self):
        try:
            key_exists = os.path.exists("secret.key") and os.path.getsize("secret.key") > 0
            salt_exists = os.path.exists("salt.bin") and os.path.getsize("salt.bin") > 0
            return key_exists and salt_exists
        except:
            return False

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def login(self):
        password = self.password_entry.get()
        if enc.verify_password(password):
            self.key = enc.derive_fernet_key_from_password(password)
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Invalid master password")

    def sign_up(self):
        password = self.password_entry.get()
        confirm_password = simpledialog.askstring("Confirm Password", "Re-enter master password:", show="*")

        if password == confirm_password:
            enc.setup_master_password(password)
            self.key = enc.derive_fernet_key_from_password(password)
            # check if vault directory exists and contains files
            if os.path.exists("vault") and os.listdir("vault"):
                sure = messagebox.askyesno("Are you sure?", f"Are you sure you want to create a new account? Some passwords already exist in the vault. They will be lost if you proceed.")
                if not sure:
                    return
                for file in os.listdir("vault"):
                    os.remove(f"vault/{file}")                    
            self.clear_screen()
            messagebox.showinfo("Success", "Sign up successful!")
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Passwords do not match")

    def show_initial_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Master Password:").pack(pady=10)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)
        self.password_entry.focus_set()

        key_present = self.check_key_presence()
        if key_present:
            tk.Button(self.root, text="Login", command=self.login).pack(pady=5)
            self.password_entry.bind("<Return>", lambda _: self.login())
        else:
            tk.Button(self.root, text="Sign Up", command=self.sign_up).pack(pady=5)
            tk.Label(self.root, text="No master password found. Please sign up or upload secret.key and salt.bin to the root directory of the project").pack(pady=5)
            self.password_entry.bind("<Return>", lambda _: self.sign_up())

    def show_main_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Password Manager").pack(pady=10)

        self.password_display = tk.Frame(self.root)
        self.password_display.pack(pady=5)

        tk.Button(self.root, text="Add password", command=self.show_add_password_dialog).pack(pady=5)
        tk.Button(self.root, text="Change Master Password", command=self.show_change_master_password).pack(pady=5)

        self.update_password_display()

    def update_password_display(self):
        def copy_password(password):
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
        for widget in self.password_display.winfo_children():
            widget.destroy()

        for file in os.listdir("vault"):
            service = file.split(".")[0]
            password = self.load_password(service)
            frame = tk.Frame(self.password_display)
            frame.pack(fill='x', pady=2)
            tk.Label(frame, text=f"{service}: {password}", anchor='w').pack(side='left', fill='x', expand=True)
            tk.Button(frame, text="Delete", command=lambda s=service: self.delete_password(s)).pack(side='right')
            tk.Button(frame, text="Change", command=lambda s=service: self.change_password(s)).pack(side='right')
            tk.Button(frame, text="Copy", command=lambda p=password: copy_password(p)).pack(side='right')

    def show_add_password_dialog(self):
        password_window = tk.Toplevel(self.root)
        password_window.title("Add Password")

        tk.Label(password_window, text="Enter Service:").pack(pady=10)
        service_entry = tk.Entry(password_window)
        service_entry.pack(pady=5)
        service_entry.focus_set()

        tk.Label(password_window, text="Enter Password:").pack(pady=10)
        password_entry = tk.Entry(password_window, show="*")
        password_entry.pack(pady=5)
        password_entry.bind("<Return>", lambda _: submit_password())

        def submit_password():
            service = service_entry.get()
            password = password_entry.get()
            self.save_password(service, password)
            messagebox.showinfo("Success", "Password saved successfully!")
            password_window.destroy()
            self.update_password_display()

        tk.Button(password_window, text="Save password", command=submit_password).pack(pady=10)

    def change_password(self, service):
        new_password = simpledialog.askstring("Change Password", f"Enter new password for {service}:", show="*")
        if new_password:
            self.save_password(service, new_password, True)
            messagebox.showinfo("Success", "Password changed successfully!")
            self.update_password_display()
    
    def delete_password(self, service):
        sure = messagebox.askyesno("Are you sure?", f"Are you sure you want to delete the password for {service}?")
        if sure:
            os.remove(f"vault/{service}.enc")
            messagebox.showinfo("Success", "Password deleted successfully!")
            self.update_password_display()

    def show_change_master_password(self):
        change_window = tk.Toplevel(self.root)
        change_window.title("Change Master Password")

        tk.Label(change_window, text="Old master password:").pack(pady=10)
        old_password_entry = tk.Entry(change_window, show="*")
        old_password_entry.pack(pady=5)
        old_password_entry.focus_set()

        tk.Label(change_window, text="New master password:").pack(pady=10)
        new_password_entry = tk.Entry(change_window, show="*")
        new_password_entry.pack(pady=5)

        tk.Label(change_window, text="Confirm new master password:").pack(pady=10)
        confirm_password_entry = tk.Entry(change_window, show="*")
        confirm_password_entry.pack(pady=5)
        confirm_password_entry.bind("<Return>", lambda _: change_password())

        def change_password():
            old_password = old_password_entry.get()
            if not enc.verify_password(old_password):
                messagebox.showerror("Error", "Invalid old master password")
                return
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()
            if not new_password:
                messagebox.showerror("Error", "New master password cannot be empty")
                return
            
            if new_password == confirm_password:
                sure = messagebox.askyesno("Are you sure?", "Are you sure you want to change the master password?")
                if not sure:
                    change_window.destroy()
                    return
                
                new_key = enc.setup_master_password(new_password)

                # encrypt current passwords with new key
                for file in os.listdir("vault"):
                    service = file.split(".")[0]
                    password = self.load_password(service)
                    self.save_password(service, password, True, new_key)
                
                self.key = new_key
                messagebox.showinfo("Success", "Master password changed successfully!")
                change_window.destroy()
            else:
                messagebox.showerror("Error", "Passwords do not match")

        tk.Button(change_window, text="Change password", command=change_password).pack(pady=10)

    def save_password(self, service, password, overwrite=False, prefered_key=None):
        # check if vault directory exists
        if not os.path.exists("vault"):
            os.mkdir("vault")

        # check if service already exists
        if os.path.exists(f"vault/{service}.enc") and not overwrite:
            # ask user if they want to overwrite
            overwrite = messagebox.askyesno("Overwrite", f"Password for {service} already exists. Do you want to overwrite it?")
            if not overwrite:
                return
        if prefered_key:
            encrypted_password = enc.encrypt_content(str(password), prefered_key)
            with open(f"vault/{service}.enc", "wb") as file:
                file.write(encrypted_password)
            return
        encrypted_password = enc.encrypt_content(str(password), self.key)
        with open(f"vault/{service}.enc", "wb") as file:
            file.write(encrypted_password)

    def load_password(self, service):
        try:
            with open(f"vault/{service}.enc", "rb") as file:
                encrypted_password = file.read()
            decrypted_password = enc.decrypt_content(encrypted_password, self.key)
            return decrypted_password
        except FileNotFoundError:
            return None


def main():
    root = tk.Tk()
    PasswordManagerApp(root)
    window_width = 600
    window_height = 400
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width / 2) - (window_width / 2)
    y = (screen_height / 2) - (window_height / 2)
    root.geometry(f"{window_width}x{window_height}+{int(x)}+{int(y)}")
    root.mainloop()


if __name__ == "__main__":
    main()
