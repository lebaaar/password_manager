import subprocess
import os
import sys
import json
import time

def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        __import__(package)

packages = ["bcrypt", "cryptography", "tkinter", "Levenshtein"]
for package in packages:
    install_and_import(package)

import tkinter
from tkinter import ttk
from tkinter import messagebox
from ttkthemes import ThemedTk
import Levenshtein

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
    
    def validate_json(self, file_path):
        try:
            with open(file_path, "r") as file:
                json.load(file)
            return True
        except:
            return False

    def ensure_files(self):
        vault_file_path = "vault.json"
        categories_file_path = "categories.json"

        # Ensure categories.json exists
        if not os.path.exists("categories.json"):
            with open(categories_file_path, "w") as file:
                file.write("[]")
        
        # Ensure vault.json exists and is not empty
        if not os.path.exists(vault_file_path) or os.path.getsize(vault_file_path) == 0:
            with open(vault_file_path, 'w') as file:
                json.dump({}, file)
        else:
            if not self.validate_json(vault_file_path):
                with open(vault_file_path, 'w') as file:
                    file.write("{}")
    
    # auth management
    def check_key_presence(self):
        try:
            key_exists = os.path.exists("secret.key") and os.path.getsize("secret.key") > 0
            salt_exists = os.path.exists("salt.bin") and os.path.getsize("salt.bin") > 0
            return key_exists and salt_exists
        except:
            return False
    
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
            
            # Check if vault.json contains any passwords
            with open("vault.json", "r") as file:
                vault = json.load(file)
            if vault:
                sure = messagebox.askyesno("Are you sure?", f"Are you sure you want to create a new account? Some passwords already exist in the vault. They will be lost if you proceed.")
                if not sure:
                    return
                with open("vault.json", "w") as file:
                    file.write("{}")
                
            self.clear_screen()
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Passwords do not match")

    # categoy management
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

    # ui management    
    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

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

    def on_manage_categories_window_close(self, setter_x, setter_y, service=None, password=None, username=None, email=None, category=None, notes=None):
        self.window_position = (setter_x, setter_y)
        self.manage_categories_window.destroy()
        try: 
            self.password_window.destroy()
        except:
            pass
        print("on manage categories window close")
        print(f"service: {service}, password: {password}, username: {username}, email: {email}, category: {category}, notes: {notes}")
        self.show_password_setter(service=service, password=password, username=username, email=email, category=category, notes=notes)

    # service management
    def get_all_service_content(self, order=None, ascending=False):
        with open("vault.json", "r") as file:
            vault = json.load(file)
        
        # Decrypt passwords
        for _, content in vault.items():
            encrypted_password = content["password"]
            content["password"] = enc.decrypt_content(encrypted_password, self.key)
        
        # Sort 
        if order:
            if order == "Date":
                return dict(sorted(vault.items(), key=lambda x: x[1]["timestamp"], reverse=not ascending))
            elif order == "Name":
                return dict(sorted(vault.items(), key=lambda x: x[0], reverse=not ascending))
            elif order == "Category":
                return dict(sorted(vault.items(), key=lambda x: x[1]["category"], reverse=not ascending))
        return vault

    def get_service_content(self, service):
        with open("vault.json", "r") as file:
            vault = json.load(file)
        if service in vault:
            content = vault[service]
            # decrypt password 
            encrypted_password = content["password"]
            content["password"] = enc.decrypt_content(encrypted_password, self.key)
            return content
        else:
            return None

    def save_service_contnet(
            self, service, password, username=None, email=None, category=None, notes=None, 
            overwrite=False, prefered_key=None, rename_service_to=None
        ):
        print("Save service content")
        print(f"overwrite: {overwrite} for service: {service} with password: {password} and username: {username} and email: {email} and category: {category} and notes: {notes} and prefered_key: {prefered_key} and rename_service_to: {rename_service_to}")
        # ensure vault.json exists
        if not os.path.exists("vault.json"):
            with open("vault.json", "w") as file:
                file.write("{}")
                
        with open("vault.json", "r") as file:
            vault = json.load(file)

        if not overwrite and service in vault:
            overwrite = messagebox.askyesno("Overwrite", f"Password for {service} already exists. Do you want to overwrite it?")
            if not overwrite:
                return
        
        if rename_service_to:
            # verify if service exists
            if service in vault:
                vault[rename_service_to] = vault.pop(service)
                service = rename_service_to
        
        if prefered_key:
            encrypted_password = enc.encrypt_content(str(password), prefered_key).decode()
            vault[service] = {"password": encrypted_password, "timestamp": int(time.time())}
            with open("vault.json", "w") as file:
                json.dump(vault, file)
            return
        
        encrypted_password = enc.encrypt_content(str(password), self.key).decode()
        vault[service] = {
            "username": username,
            "email": email,
            "password": encrypted_password,
            "category": category, 
            "notes": notes,
            "timestamp": int(time.time())
        }

        # write final content to vault.json
        with open("vault.json", "w") as file:
            json.dump(vault, file)

        self.update_password_display()
        self.adjust_window_size()

    def delete_service_contnet(self, service):
        sure = messagebox.askyesno("Are you sure?", f"Are you sure you want to delete the content for {service}?")
        if not sure:
            return
        with open("vault.json", "r") as file:
            vault = json.load(file)
        if service in vault:
            del vault[service]
            with open("vault.json", "w") as file:
                json.dump(vault, file)
            self.update_password_display()
            self.adjust_window_size()
        else:
            messagebox.showerror("Error", f"No content to match {service}")

    # screens
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

        # Left side
        left_frame = ttk.Frame(self.root)
        left_frame.pack(side='left', fill='y', padx=5)

        # Search option
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(pady=5)
        ttk.Label(search_frame, text="Search:").pack(side='left')
        search_entry = ttk.Entry(search_frame, width=15)
        search_entry.pack(side='left')
        search_button = ttk.Button(search_frame, text="Search", command=lambda: self.update_password_display(search_query=search_entry.get()))
        search_button.pack(side='left')
        search_button.bind("<Return>", lambda _: search_button.invoke())

        # Sort options
        sort_frame = ttk.Frame(left_frame)
        sort_frame.pack(pady=5)
        ttk.Label(sort_frame, text="Sort:").pack(side='left')
        sort_dropdown = ttk.Combobox(sort_frame, values=["Date", "Name", "Category"], state="readonly", width=10)
        sort_dropdown.current(0)
        sort_dropdown.pack(side='left')
        sort_dropdown.bind("<<ComboboxSelected>>", lambda _: self.update_password_display(sort=sort_dropdown.get()))
        self.sort_button = ttk.Button(sort_frame, text="▼", command=toggle_sort_order)
        self.sort_button.pack(side='left')
        self.sort_button.bind("<Return>", lambda _: self.sort_button.invoke())

        # Change master password button
        change_master_password_button = ttk.Button(left_frame, text="Change Master Password", command=self.show_change_master_password)
        change_master_password_button.pack(pady=5)
        change_master_password_button.bind("<Return>", lambda _: change_master_password_button.invoke())

        # right side
        right_frame = ttk.Frame(self.root)
        right_frame.pack(side='right', fill='y', padx=5)

        # Add password button
        add_password_button = ttk.Button(self.root, text="Add password", command=self.show_password_setter)
        add_password_button.pack(pady=5)
        add_password_button.bind("<Return>", lambda _: add_password_button.invoke())

        # Password content display
        self.password_display = ttk.Frame(self.root)
        self.password_display.pack(pady=5)
        
        self.update_password_display()
        self.adjust_window_size()
    
    def update_password_display(self, sort="Date", ascending=False, search_query=None):
        
        def levenshtein_fuzzy_search(query, data, max_distance=5):
            results = {}
            for key in data.keys():
                distance = Levenshtein.distance(query, key)
                if distance <= max_distance:
                    results[key] = data[key]
            return results

        def copy_password(password):
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()

        for widget in self.password_display.winfo_children():
            widget.destroy()
        
        all_contnet = self.get_all_service_content(sort, ascending)
        if search_query and search_query != "" and search_query.strip() != "": 
            results = levenshtein_fuzzy_search(search_query, all_contnet)
            all_contnet = results

        for service, content in all_contnet.items():
            username = content["username"]
            email = content["email"]
            password = content["password"]
            category = content["category"]
            notes = content.get("notes", None)
            frame = ttk.Frame(self.password_display)
            frame.pack(fill='x', pady=2)

            left_frame = ttk.Frame(frame)
            left_frame.pack(side='left', fill='x', expand=True)

            right_frame = ttk.Frame(frame)
            right_frame.pack(side='right', fill='x', expand=True)

            info_frame = ttk.Frame(left_frame)
            info_frame.pack(side='top', fill='x', expand=True)

            ttk.Label(info_frame, text=f"{service}", anchor='w', font=("Helvetica", 14)).pack(side='top', fill='x', expand=True)
            ttk.Label(info_frame, text=f"{category if category else 'No category'}", anchor='w', font=("Helvetica", 10)).pack(side='top', fill='x', expand=True)

            # Buttons
            copy_button = ttk.Button(right_frame, text="Copy", command=lambda p=password: copy_password(p))
            copy_button.pack(side='right', anchor='e', padx=5)
            copy_button.bind("<Return>", lambda _: copy_button.invoke())

            change_button = ttk.Button(right_frame, text="View", command=lambda s=service, p=password, u=username, e=email, c=category, n=notes: self.show_password_setter(service=s, password=p, username=u, email=e, category=c, notes=n))
            change_button.pack(side='right', anchor='e')
            change_button.bind("<Return>", lambda _: change_button.invoke())

            delete_button = ttk.Button(right_frame, text="Delete", command=lambda s=service: self.delete_service_content(s))
            delete_button.pack(side='right', anchor='e')
            delete_button.bind("<Return>", lambda _: delete_button.invoke())

    def show_password_setter(self, service=None, password=None, username=None, email=None, category=None, notes=None):
        # check if change mode
        change_mode = service is not None and password is not None and self.get_service_content(service) is not None
        print("Show password setter")
        print(f"Change mode: {change_mode}")
        original_service = service
        
        self.password_window = tkinter.Toplevel(self.root)
        if change_mode:
            self.password_window.title("Change Password")
        else:
            self.password_window.title("Add Password")
        try:
            if self.window_position:
                x, y = self.window_position
                self.password_window.geometry(f"400x450+{x}+{y}")
            self.password_window.title("Manage Categories")
        except Exception:
            self.password_window.geometry("400x450")
            pass
        self.password_window.bind("<Escape>", lambda _: self.password_window.destroy())

        # Service
        ttk.Label(self.password_window, text="Enter Service*:").pack(pady=10)
        service_entry = ttk.Entry(self.password_window, width=30)
        service_entry.pack(pady=5)
        service_entry.focus_set()
        if service:
            service_entry.insert(0, service)

        # Username
        ttk.Label(self.password_window, text="Enter username:").pack(pady=10)
        username_entry = ttk.Entry(self.password_window, width=50)
        username_entry.pack(pady=5)
        if username:
            username_entry.insert(0, username)

        # Email
        ttk.Label(self.password_window, text="Enter email:").pack(pady=10)
        email_entry = ttk.Entry(self.password_window, width=50)
        email_entry.pack(pady=5)
        if email:
            email_entry.insert(0, email)

        # Category
        category_frame = ttk.Frame(self.password_window)
        category_frame.pack(pady=5)

        ttk.Label(category_frame, text="Category:").pack(side='left')
        cateories = self.get_categories()
        cateories.insert(0, "None")
        category_entry = ttk.Combobox(category_frame, values=cateories, state="readonly")
        category_entry.current(0)
        category_entry.pack(side='left')
        if category:
            category_entry.set(category)
        
        # Add category button
        print(f"Add category button clicked with service: {service}, password: {password}, username: {username}, email: {email}, category: {category}, notes: {notes}")
        ttk.Button(category_frame, text="Manage Categories", command=lambda: self.show_manage_categories(
            service_r=service_entry.get(), password_r=password_entry.get(), username_r=username_entry.get(), email_r=email_entry.get(), category_r=category_entry.get(), notes_r=notes_entry.get()
        )).pack(side='left')

        # Notes
        ttk.Label(self.password_window, text="Enter notes:").pack(pady=10)
        notes_entry = ttk.Entry(self.password_window, width=50)
        notes_entry.pack(pady=5)
        if notes:
            notes_entry.insert(0, notes)

        ttk.Label(self.password_window, text="Enter Password*:").pack(pady=10)
        password_entry = ttk.Entry(self.password_window, width=50)
        password_entry.pack(pady=5)
        if password:
            password_entry.insert(0, password)

        def submit_content():
            print("Submit content with chnage mode: ", change_mode)
            service = service_entry.get()
            password = password_entry.get()
            username = username_entry.get()
            email = email_entry.get()
            category = category_entry.get()
            notes = notes_entry.get()
            if not service or not password:
                messagebox.showerror("Error", "Service is a required field") if not service else messagebox.showerror("Error", "Password is a required field")
                return
            if change_mode:
                # check if new name already exists
                if self.get_service_content(service) is not None and service != original_service:
                    messagebox.showerror("Error", f"Service {service} already exists")
                    return
                self.save_service_contnet(
                    service=original_service, 
                    password=password, 
                    username=username,
                    email=email,
                    category="" if category == "None" else category,
                    notes=notes,
                    overwrite=True,
                    prefered_key=None,
                    rename_service_to=service
                )
            else:
                self.save_service_contnet(
                    service=service, 
                    password=password, 
                    username=username,
                    email=email,
                    category="" if category == "None" else category,
                    notes=notes
                )
            self.password_window.destroy()
            self.update_password_display()

        save_button = ttk.Button(self.password_window, text="Save", command=submit_content)
        save_button.pack(pady=10)
        save_button.bind("<Return>", lambda _: submit_content())

        self.password_window.bind("<Escape>", lambda _: self.password_window.destroy())

    def show_manage_categories(self, service_r=None, password_r=None, username_r=None, email_r=None, category_r=None, notes_r=None):
        self.manage_categories_window = tkinter.Toplevel(self.root)
        self.manage_categories_window.protocol("WM_DELETE_WINDOW", lambda: self.on_manage_categories_window_close(
            self.password_window.winfo_x(), self.password_window.winfo_y(),
            service=service_r, password=password_r, username=username_r, email=email_r, category=category_r, notes=notes_r
        ))
        try:
            if self.window_position:
                x, y = self.window_position
                self.manage_categories_window.geometry(f"400x200+{x}+{y}")
            self.manage_categories_window.title("Manage Categories")
        except Exception:
            self.manage_categories_window.geometry("400x200")
            pass
        self.manage_categories_window.bind("<Escape>", lambda _:self.on_manage_categories_window_close(
            self.password_window.winfo_x(), self.password_window.winfo_y(),
            service=service_r, password=password_r, username=username_r, email=email_r, category=category_r, notes=notes_r
        ))
        
        def delete_category(category):
            self.remove_category(category)
            x = self.manage_categories_window.winfo_x()
            y = self.manage_categories_window.winfo_y()
            self.window_position = (x, y)
            self.manage_categories_window.destroy()
            self.show_manage_categories(
                service_r=service_r, password_r=password_r, username_r=username_r, email_r=email_r, category_r=category_r, notes_r=notes_r
            )

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
                self.show_manage_categories(
                    service_r=service_r, password_r=password_r, username_r=username_r, email_r=email_r, category_r=category_r, notes_r=notes_r
                )

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

                # Encrypt current passwords with new key
                with open("vault.json", "r") as file:
                    vault = json.load(file)
                for service, content in vault.items():
                    encrypted_password = enc.encrypt_content(content["password"], new_key).decode()
                    content["password"] = encrypted_password

                with open("vault.json", "w") as file:
                    json.dump(vault, file)

                self.key = new_key
                change_window.destroy()
            else:
                messagebox.showerror("Error", "Passwords do not match")

        change_password_button = ttk.Button(change_window, text="Change password", command=change_master_password)
        change_password_button.pack(pady=10)
        change_password_button.bind("<Return>", lambda _: change_master_password())


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
