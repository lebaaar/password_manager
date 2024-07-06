import subprocess
import os
import sys
import json

def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        __import__(package)

packages = ["bcrypt", "cryptography", "tkinter"]
for package in packages:
    install_and_import(package)

import tkinter
from tkinter import ttk
from tkinter import messagebox
from ttkthemes import ThemedTk

try:
    import encryption as enc
except ImportError:
    messagebox.showerror("Error", "encryption.py not found. Please make sure encryption.py is in the same directory as main.py")

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
        self.ensure_files()

    def check_key_presence(self):
        try:
            key_exists = os.path.exists("secret.key") and os.path.getsize("secret.key") > 0
            salt_exists = os.path.exists("salt.bin") and os.path.getsize("salt.bin") > 0
            return key_exists and salt_exists
        except:
            return False
    
    def ensure_files(self):
        if not os.path.exists("vault"):
            os.mkdir("vault")
        if not os.path.exists("categories.json"):
            with open("categories.json", "w") as file:
                file.write("[]")
        if not os.path.exists("vault.json"):
            with open("vault.json", "w") as file:
                file.write("{}")
        
    def get_categories(self):
        with open("categories.json", "r") as file:
            return json.load(file)

    def add_category(self, category):
        categories = self.get_categories()
        if category not in categories:
            categories.append(category)
            with open("categories.json", "w") as file:
                json.dump(categories, file)
        else:
            messagebox.showerror("Error", "Category already exists")

    def remove_category(self, category):
        categories = self.get_categories()
        if category in categories:
            categories.remove(category)
            with open("categories.json", "w") as file:
                json.dump(categories, file)
        else:
            messagebox.showerror("Error", "Category does not exist")

    def rename_category(self, old_category, new_category):
        categories = self.get_categories()
        if new_category in categories:
            messagebox.showerror("Error", "Category already exists")
            return False
        if old_category in categories:
            categories.remove(old_category)
            categories.append(new_category)
            with open("categories.json", "w") as file:
                json.dump(categories, file)
            return True
        else:
            messagebox.showerror("Error", "Category does not exist")
            return False

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def load_password(self, service):
        try:
            with open(f"vault/{service}.enc", "rb") as file:
                encrypted_password = file.read()
            decrypted_password = enc.decrypt_content(encrypted_password, self.key)
            return decrypted_password
        except FileNotFoundError:
            return None

    def login(self, event=None):
        password = self.password_entry.get()
        if enc.verify_password(password):
            self.key = enc.derive_fernet_key_from_password(password)
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Invalid master password")

    def sign_up(self, event=None):
        password = self.master_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

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
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Passwords do not match")

    def adjust_window_size(self, window=None):
        target_window = self.root if window is None else window
        target_window.update_idletasks()
        window_width = target_window.winfo_reqwidth()
        window_height = target_window.winfo_reqheight()
        screen_width = target_window.winfo_screenwidth()
        screen_height = target_window.winfo_screenheight()
        window_width += 50  # Adjust dimensions as needed
        window_height += 50  # Adjust dimensions as needed
        x = (screen_width / 2) - (window_width / 2)
        y = (screen_height / 2) - (window_height / 2)
        target_window.geometry(f"{int(window_width)}x{int(window_height)}+{int(x)}+{int(y)}")

    def show_initial_screen(self):
        self.clear_screen()
        self.root.bind("<Escape>", lambda _: self.root.destroy())

        key_present = self.check_key_presence()
        if key_present:
            ttk.Label(self.root, text="Master Password:").pack(pady=10)
            self.password_entry = ttk.Entry(self.root, show="*")
            self.password_entry.pack(pady=5)
            self.password_entry.focus_set()
            login_button = ttk.Button(self.root, text="Login", command=self.login)
            login_button.pack(pady=5)
            login_button.bind("<Return>", lambda _: self.login())
            self.password_entry.bind("<Return>", self.login)
            self.root.bind_class("Button", "<Return>", lambda event: event.widget.invoke())
        else:
            ttk.Label(self.root, text="Choose Master Password:").pack(pady=5)
            self.master_password_entry = ttk.Entry(self.root, show="*")
            self.master_password_entry.pack(pady=5)
            ttk.Label(self.root, text="Confirm Master Password:").pack(pady=5)
            self.confirm_password_entry = ttk.Entry(self.root, show="*")
            self.confirm_password_entry.pack(pady=5)

            sign_up_button = ttk.Button(self.root, text="Sign Up", command=self.sign_up)
            sign_up_button.pack(pady=5)
            sign_up_button.bind("<Return>", lambda _: self.sign_up())
            self.master_password_entry.bind("<Return>", self.sign_up)
            self.confirm_password_entry.bind("<Return>", self.sign_up)

    def show_main_screen(self):
        self.current_order = False
        def toggle_sort_order():
                self.current_order = not self.current_order
                # Update the button's text based on the current order
                self.sort_button.config(text="▲" if self.current_order else "▼")
                self.update_password_display(sort=sort_dropdown.get(), ascending=self.current_order)
        self.clear_screen()

        ttk.Label(self.root, text="Password Manager").pack(pady=10)

        sort_frame = ttk.Frame(self.root)
        sort_frame.pack(pady=5)

        ttk.Label(sort_frame, text="Sort:").pack(side='left')
        sort_dropdown = ttk.Combobox(sort_frame, values=["Date", "Name"], state="readonly")
        sort_dropdown.current(0)
        sort_dropdown.pack(side='left')
        sort_dropdown.bind("<<ComboboxSelected>>", lambda _: self.update_password_display(sort=sort_dropdown.get()))

        self.sort_button = ttk.Button(sort_frame, text="▼", command=toggle_sort_order)

        self.sort_button.pack(side='left')
        self.sort_button.bind("<Return>", lambda _: self.sort_button.invoke())

        self.password_display = ttk.Frame(self.root)
        self.password_display.pack(pady=5)

        add_password_button = ttk.Button(self.root, text="Add password", command=self.show_password_setter)
        add_password_button.pack(pady=5)
        add_password_button.bind("<Return>", lambda _: add_password_button.invoke())
        change_master_password_button = ttk.Button(self.root, text="Change Master Password", command=self.show_change_master_password)
        change_master_password_button.pack(pady=5)
        change_master_password_button.bind("<Return>", lambda _: change_master_password_button.invoke())
        
        self.update_password_display()
        self.adjust_window_size()
    
    def update_password_display(self, sort="Date", ascending=False):
        def copy_password(password):
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()

        def get_sorted_files():
            if not os.path.exists("vault"):
                os.mkdir("vault")
            files = os.listdir("vault")
            if sort == "Date":
                files.sort(key=lambda x: os.path.getmtime(f"vault/{x}"), reverse=not ascending)
            elif sort == "Name":
                files.sort(key=lambda x: x.lower())
                if not ascending: files.reverse()
            return files

        for widget in self.password_display.winfo_children():
            widget.destroy()

        for file in get_sorted_files():
            service = file.split(".")[0]
            password = self.load_password(service)
            frame = ttk.Frame(self.password_display)
            frame.pack(fill='x', pady=2)
            ttk.Label(frame, text=f"{service}: {password}", anchor='w').pack(side='left', fill='x', expand=True)

            # Buttons
            copy_button = ttk.Button(frame, text="Copy", command=lambda p=password: copy_password(p))
            copy_button.pack(side='left')
            copy_button.bind("<Return>", lambda _: copy_button.invoke())

            change_button = ttk.Button(frame, text="Change", command=lambda s=service, p=password: self.show_password_setter(service=s, password=p))
            change_button.pack(side='left')
            change_button.bind("<Return>", lambda _: change_button.invoke())

            delete_button = ttk.Button(frame, text="Delete", command=lambda s=service: self.delete_password(s))
            delete_button.pack(side='left')
            delete_button.bind("<Return>", lambda _: delete_button.invoke())


    def show_password_setter(self, service=None, username=None, category=None, password=None):
        change_mode = service is not None and password is not None
        original_service = service
        
        self.password_window = tkinter.Toplevel(self.root)
        if change_mode:
            self.password_window.title("Change Password")
        else:
            self.password_window.title("Add Password")
        try:
            if self.window_position:
                x, y = self.window_position
                self.password_window.geometry(f"400x400+{x}+{y}")
            self.password_window.title("Manage Categories")
        except Exception:
            self.password_window.geometry("400x400")
            pass
        self.password_window.bind("<Escape>", lambda _: self.password_window.destroy())

        # Service
        ttk.Label(self.password_window, text="Enter Service*:").pack(pady=10)
        service_entry = ttk.Entry(self.password_window, width=30)
        service_entry.pack(pady=5)
        service_entry.focus_set()
        service_entry.bind("<Return>", lambda _: submit_password())
        if service:
            service_entry.insert(0, service)

        # Username
        ttk.Label(self.password_window, text="Enter username:").pack(pady=10)
        username_entry = ttk.Entry(self.password_window, width=50)
        username_entry.pack(pady=5)
        if username:
            username_entry.insert(0, username)

        # Category
        category_frame = ttk.Frame(self.password_window)
        category_frame.pack(pady=5)

        ttk.Label(category_frame, text="Category:").pack(side='left')
        cateories = self.get_categories()
        cateories.insert(0, "None")
        sort_dropdown = ttk.Combobox(category_frame, values=cateories, state="readonly")
        sort_dropdown.current(0)
        sort_dropdown.pack(side='left')
        if category:
            sort_dropdown.set(category)
        
        # Add category button
        ttk.Button(category_frame, text="Manage Categories", command=lambda: self.show_manage_categories()).pack(side='left')

        # Notes
        ttk.Label(self.password_window, text="Enter notes:").pack(pady=10)
        notes_entry = ttk.Entry(self.password_window, width=50)
        notes_entry.pack(pady=5)

        ttk.Label(self.password_window, text="Enter Password*:").pack(pady=10)
        password_entry = ttk.Entry(self.password_window, width=50)
        password_entry.pack(pady=5)
        password_entry.bind("<Return>", lambda _: submit_password())
        if password:
            password_entry.insert(0, password)

        def submit_password():
            service = service_entry.get()
            password = password_entry.get()
            if not service or not password:
                messagebox.showerror("Error", "Service and password cannot be empty")
                return
            if change_mode:
                self.save_password(original_service, password, True, None, service)
            else:
                self.save_password(service, password)
            self.password_window.destroy()
            self.update_password_display()

        save_button = ttk.Button(self.password_window, text="Save", command=submit_password)
        save_button.pack(pady=10)
        save_button.bind("<Return>", lambda _: submit_password())

        self.password_window.bind("<Escape>", lambda _: self.password_window.destroy())

    def on_manage_categories_window_close(self, setter_x, setter_y):
        self.window_position = (setter_x, setter_y)
        self.manage_categories_window.destroy()
        try: 
            self.password_window.destroy()
        except:
            pass
        self.show_password_setter()

    def show_manage_categories(self):
        self.manage_categories_window = tkinter.Toplevel(self.root)
        self.manage_categories_window.protocol("WM_DELETE_WINDOW", lambda: self.on_manage_categories_window_close(self.password_window.winfo_x(), self.password_window.winfo_y()))
        try:
            if self.window_position:
                x, y = self.window_position
                self.manage_categories_window.geometry(f"400x200+{x}+{y}")
            self.manage_categories_window.title("Manage Categories")
        except Exception:
            self.manage_categories_window.geometry("400x200")
            pass
        self.manage_categories_window.bind("<Escape>", lambda _: self.on_manage_categories_window_close())
        
        def delete_category(category):
            self.remove_category(category)
            x = self.manage_categories_window.winfo_x()
            y = self.manage_categories_window.winfo_y()
            self.window_position = (x, y)
            self.manage_categories_window.destroy()
            self.show_manage_categories()

        categories = self.get_categories()
        for category in categories:
            frame = ttk.Frame(self.manage_categories_window)
            frame.pack(fill='x', pady=2)
            ttk.Label(frame, text=category, anchor='w').pack(side='left', fill='x', expand=True)

            # Buttons
            change_button = ttk.Button(frame, text="Rename", command=lambda c=category: self.show_rename_category(category=c))
            change_button.pack(side='left')
            change_button.bind("<Return>", lambda _: change_button.invoke())

            delete_button = ttk.Button(frame, text="Delete", command=lambda c=category: delete_category(c))
            delete_button.pack(side='left')
            delete_button.bind("<Return>", lambda _: delete_button.invoke())

        def add_category():
            category = category_entry.get()
            if not category:
                print("Category cannot be empty")
                messagebox.showerror("Error", "Category cannot be empty")
                try:
                    category_entry.focus_set()
                except:
                    self.manage_categories_window.focus_set()
            else:
                self.add_category(category)
                x = self.manage_categories_window.winfo_x()
                y = self.manage_categories_window.winfo_y()
                self.window_position = (x, y)
                self.manage_categories_window.destroy()
                self.show_manage_categories()

        # Add category entry
        ttk.Label(self.manage_categories_window, text="Add new category:").pack(pady=10)
        category_entry = ttk.Entry(self.manage_categories_window, width=50)
        category_entry.pack(pady=5)
        category_entry.focus_set()
        category_entry.bind("<Return>", lambda _: add_category())

        # Add category button
        add_category_button = ttk.Button(self.manage_categories_window, text="Add Category", command=add_category)
        add_category_button.pack(pady=10)
        add_category_button.bind("<Return>", lambda _: add_category())

        self.adjust_window_size(self.manage_categories_window)

    def show_rename_category(self, category):
        rename_window = tkinter.Toplevel(self.root)
        rename_window.title("Rename Category")
        rename_window.bind("<Escape>", lambda _: rename_window.destroy())
        rename_window.geometry("400x300")

        def rename_category():
            x = self.manage_categories_window.winfo_x()
            y = self.manage_categories_window.winfo_y()
            self.window_position = (x, y)
            new_category = category_entry.get()
            if not new_category:
                messagebox.showerror("Error", "Category cannot be empty")
                return
            if new_category == category:
                rename_window.destroy()
                return
            
            if self.rename_category(category, new_category):
                # get current window position

                rename_window.destroy()
                self.manage_categories_window.destroy()
                self.show_manage_categories()

        ttk.Label(rename_window, text="Category name:").pack(pady=10)
        category_entry = ttk.Entry(rename_window, width=50)
        category_entry.pack(pady=5)
        category_entry.insert(0, category)
        category_entry.focus_set()
        category_entry.bind("<Return>", lambda _: rename_category())

        rename_category_button = ttk.Button(rename_window, text="Rename Category", command=rename_category)
        rename_category_button.pack(pady=10)
        rename_category_button.bind("<Return>", lambda _: rename_category())


    def show_change_master_password(self):
        change_window = tkinter.Toplevel(self.root)
        change_window.title("Change Master Password")
        change_window.bind("<Escape>", lambda _: change_window.destroy())
        change_window.geometry("400x300")

        ttk.Label(change_window, text="Old master password:").pack(pady=10)
        old_password_entry = ttk.Entry(change_window, width=50)
        old_password_entry.pack(pady=5)
        old_password_entry.focus_set()

        ttk.Label(change_window, text="New master password:").pack(pady=10)
        new_password_entry = ttk.Entry(change_window, width=50)
        new_password_entry.pack(pady=5)

        ttk.Label(change_window, text="Confirm new master password:").pack(pady=10)
        confirm_password_entry = ttk.Entry(change_window, width=50)
        confirm_password_entry.pack(pady=5)
        confirm_password_entry.bind("<Return>", lambda _: change_master_password())

        def change_master_password():
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
                change_window.destroy()
            else:
                messagebox.showerror("Error", "Passwords do not match")

        change_password_button = ttk.Button(change_window, text="Change password", command=change_master_password)
        change_password_button.pack(pady=10)
        change_password_button.bind("<Return>", lambda _: change_master_password())

    def save_password(self, service, password, overwrite=False, prefered_key=None, rename_service_to=None):
        if not os.path.exists("vault"):
            os.mkdir("vault")

        if os.path.exists(f"vault/{service}.enc") and not overwrite:
            overwrite = messagebox.askyesno("Overwrite", f"Password for {service} already exists. Do you want to overwrite it?")
            if not overwrite:
                return
        
        if rename_service_to:
            os.rename(f"vault/{service}.enc", f"vault/{rename_service_to}.enc")
            service = rename_service_to

        if prefered_key:
            encrypted_password = enc.encrypt_content(str(password), prefered_key)
            with open(f"vault/{service}.enc", "wb") as file:
                file.write(encrypted_password)
            return
        
        encrypted_password = enc.encrypt_content(str(password), self.key)
        with open(f"vault/{service}.enc", "wb") as file:
            file.write(encrypted_password)
        
        self.update_password_display()
        self.adjust_window_size()

    def delete_password(self, service):
        sure = messagebox.askyesno("Are you sure?", f"Are you sure you want to delete the password for {service}?")
        if sure:
            os.remove(f"vault/{service}.enc")
            self.update_password_display()
            self.adjust_window_size()

def main():
    root = ThemedTk(theme="arc")
    PasswordManagerApp(root)
    window_width = 300
    window_height = 200
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width / 2) - (window_width / 2)
    y = (screen_height / 2) - (window_height / 2)
    root.geometry(f"{window_width}x{window_height}+{int(x)}+{int(y)}")
    root.lift()
    # root.iconphoto(False, tkinter.PhotoImage(file="icon.png"))
    root.mainloop()

if __name__ == "__main__":
    main()
