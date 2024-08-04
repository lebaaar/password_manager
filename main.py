import subprocess
import os
import shutil
import sys
import json
import time

def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        __import__(package)

packages = ["bcrypt", "cryptography", "tkinter", "Levenshtein", "tendo", "ttkthemes"]
for package in packages:
    install_and_import(package)

import tkinter
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from tkinter import messagebox
from ttkthemes import ThemedTk
import Levenshtein
from tendo import singleton

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

        self.current_search_query = None
        self.current_filter_category = "All"
        self.current_sort = "Date"
        self.current_sort_order = False

        self.password_views = []
        self.password_display = None
        self.root_scrollbar_visible = False

        # Tracking open winows
        self.root_window_open = False
        self.password_setter_window_open = False
        self.manage_categories_window_open = False
        self.rename_category_window_open = False
        self.change_master_password_window_open = False

        self.show_initial_screen(
            self.check_key_presence() or
            self.chcek_known_value_presence()
        )
        self.ensure_files()



    # File management
    def validate_json(self, file_path):
        try:
            with open(file_path, "r") as file:
                json.load(file)
            return True
        except:
            return False

    def validate_vault(self):
        keys = ["username", "email", "password", "category", "notes", "timestamp"]
        with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
            vault = json.load(file)
        if not vault:
            return False
        for service, content in vault.items():
            for key in keys:
                if key not in content:
                    return False
        return True

    def ensure_files(self):
        vault_file_path = f"{os.path.dirname(__file__)}/vault.json"
        categories_file_path = f"{os.path.dirname(__file__)}/categories.json"
        settings_file_path = f"{os.path.dirname(__file__)}/settings.json"
        default_backup_dir_paths = ["C:\\Backups\\password_manager"]
        for backup_path in default_backup_dir_paths:
            if not os.path.exists(backup_path):
                os.makedirs(backup_path)
        settings_template = {
            "store_key": False,
            "display_passwords": True,
            "backup_dir_paths": default_backup_dir_paths
        }

        # Ensure categories.json exists
        if not os.path.exists(f"{os.path.dirname(__file__)}/categories.json"):
            with open(categories_file_path, "w") as file:
                file.write("[]")

        # Ensure settings.json exists and contains all the needed info
        if not os.path.exists(settings_file_path) or os.path.getsize(settings_file_path) == 0:
            with open(settings_file_path, "w") as file:
                json.dump(settings_template, file)
        else:
            if not self.validate_json(settings_file_path):
                with open(settings_file_path, "w") as file:
                    file.write(json.dumps(settings_template))
            else:
                # Check if all keys are present
                modified = False
                with open(settings_file_path, "r") as file:
                    settings = json.load(file)
                for necessary_key in settings_template.keys():
                    if necessary_key not in settings:
                        settings[necessary_key] = settings_template[necessary_key]
                        modified = True
                if modified:
                    with open(settings_file_path, "w") as file:
                        json.dump(settings, file)

        # Ensure vault.json exists and is not empty
        if not os.path.exists(vault_file_path) or os.path.getsize(vault_file_path) == 0:
            with open(vault_file_path, "w") as file:
                json.dump({}, file)
        else:
            if not self.validate_json(vault_file_path):
                with open(vault_file_path, "w") as file:
                    file.write("{}")

    def backup_files(self):
        """
            Backup: vault.json, categories.json, settings.json
            If master password is remebmered by the user, he can manually derive encryption key from it and use it to decrypt the files
            Method to derive encryption key from master password is in encryption.py
            Salt used is hardcoded in encryption.py
        """
        settings = self.get_settings()
        backup_dir_paths = settings["backup_dir_paths"]

        if not isinstance(backup_dir_paths, list):
            backup_dir_paths = [backup_dir_paths]

        # Backup files
        files = [
            f"{os.path.dirname(__file__)}/vault.json",
            f"{os.path.dirname(__file__)}/categories.json",
            f"{os.path.dirname(__file__)}/settings.json",
            f"{os.path.dirname(__file__)}/manual-decryption.py"
        ]
        for backup_path in backup_dir_paths:
            if os.path.isfile(backup_path):
                backup_path = os.path.dirname(backup_path)
            if not os.path.exists(backup_path):
                os.makedirs(backup_path)

            for file in files:
                try:
                    shutil.copy(file, backup_path)
                except Exception as e:
                    print(f"Error backing up {file} to {backup_path}: {e}")



    # Auth management
    def check_key_presence(self):
        try:
            if os.path.exists(f"{os.path.dirname(__file__)}/secret.key") and os.path.getsize(f"{os.path.dirname(__file__)}/secret.key") > 0:
                return True
            return False
        except:
            return False

    def chcek_known_value_presence(self):
        try:
            if os.path.exists(f"{os.path.dirname(__file__)}/known_value.bin") and os.path.getsize(f"{os.path.dirname(__file__)}/known_value.bin") > 0:
                return True
            return False
        except:
            return False

    def login(self, event=None, store_key=False):
        password = self.password_entry.get()
        if store_key:
            # Key should be stored in secret.key
            try:
                if enc.verify_password_with_stored_key(password):
                    self.key = enc.load_key_from_file()
                    self.show_main_screen()
                else:
                    messagebox.showerror("Error", "Invalid master password")
            except FileNotFoundError as e:
                messagebox.showerror("Error", f"{e}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
        else:
            # Key not stored, known value should be stored
            try:
                if enc.verify_password_without_stored_key(password):
                    self.key = enc.derive_fernet_key_from_password(password)
                    self.show_main_screen()
                else:
                    messagebox.showerror("Error", "Invalid master password")
            except FileNotFoundError as e:
                messagebox.showerror("Error", f"{e}")
            except FileExistsError as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

    def sign_up(self, event=None, store_key=False):
        password = self.master_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        if password == confirm_password:
            enc.setup_master_password(password, store_key)
            self.key = enc.derive_fernet_key_from_password(password)

            # Clear all stored passwords
            with open(f"{os.path.dirname(__file__)}/vault.json", "w") as file:
                file.write("{}")

            self.clear_screen()
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Passwords do not match")



    # Categoy management
    def get_categories(self):
        with open(f"{os.path.dirname(__file__)}/categories.json", "r") as file:
            return json.load(file)

    def add_category(self, category):
        categories = self.get_categories()
        if category not in categories:
            categories.append(category)
            with open(f"{os.path.dirname(__file__)}/categories.json", "w") as file:
                json.dump(categories, file)
        else:
            messagebox.showerror("Error", "Category already exists")

    def remove_category(self, category_plain):
        categories = self.get_categories()

        # Check if category exists
        if category_plain not in categories:
            messagebox.showerror("Error", "Category does not exist")

        # Check if category is in use
        with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
            vault = json.load(file)
        for _, content in vault.items():
            if content["category"] == category_plain:
                messagebox.showerror("Error", "Category is in use, cannot delete")
                return

        categories.remove(category_plain)
        with open(f"{os.path.dirname(__file__)}/categories.json", "w") as file:
            json.dump(categories, file)

    def rename_category(self, old_category_plain, new_category_plain):
        categories = self.get_categories()

        # Check if category exists
        if old_category_plain not in categories:
            messagebox.showerror("Error", "Category does not exist")
            return False

        # Check duplicates
        if new_category_plain in categories:
            messagebox.showerror("Error", "Category already exists")
            return False

        # Check if category is in use
        with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
            vault = json.load(file)
        for _, content in vault.items():
            if content["category"] == old_category_plain:
                sure = messagebox.askyesno("Category in use", f"Category {old_category_plain} is in use. Are you sure you want to rename it?")
                if not sure:
                    return False
                break

        # Rename category
        index = categories.index(old_category_plain)
        categories[index] = new_category_plain
        with open(f"{os.path.dirname(__file__)}/categories.json", "w") as file:
            json.dump(categories, file)

        # Update vault.json
        for _, content in vault.items():
            if content["category"] == old_category_plain:
                content["category"] = new_category_plain
        with open(f"{os.path.dirname(__file__)}/vault.json", "w") as file:
            json.dump(vault, file)
        return True



    # Service management
    def get_all_service_content(self, order=None, ascending=False):
        # Returns decrypted content
        return_content = {}

        with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
            vault = json.load(file)

        # Decrypt content
        for service_plain, content_encrypted in vault.items():
            content = self.get_service_content(service_plain)
            return_content[service_plain] = content

        return self.sort_content(return_content, order, ascending)

    def sort_content(self, content_plain, order, ascending):
        if order == "Date":
            return dict(sorted(content_plain.items(), key=lambda x: x[1]["timestamp"], reverse=not ascending))
        elif order == "Name":
            return dict(sorted(content_plain.items(), key=lambda x: x[0], reverse=not ascending))
        elif order == "Category":
            return dict(sorted(content_plain.items(), key=lambda x: x[1]["category"], reverse=not ascending))
        return content_plain

    def get_service_content(self, service_plain):
        # Returns decrypted content

        return_content = {}

        with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
            vault = json.load(file)

        if service_plain not in vault:
            return None

        content = vault[service_plain]
        for key, value in content.items():
            # Skip decryption of empty values - ""
            if not value:
                return_content[key] = ""
                continue
            # Skip decryption of timestamp and category - not encrypted
            if key in ["timestamp", "category"]:
                return_content[key] = value
                continue
            decrypted_value = enc.decrypt_content(value, self.key)
            if not decrypted_value:
                raise DecryptionError(f"Decryption failed for {service_plain} - {key}")
            return_content[key] = decrypted_value

        return return_content

    def save_service_contnet(
            self, service_plain, password_plain,
            username_plain=None, email_plain=None, category_plain=None, notes_plain=None,
            overwrite=False, prefered_key=None, rename_service_to_plain=None
        ):
        # Encrypts content and saves it to vault.json
        # Returns True if successful, False if failed/cancelled

        # Ensure vault.json exists
        if not os.path.exists(f"{os.path.dirname(__file__)}/vault.json"):
            with open(f"{os.path.dirname(__file__)}/vault.json", "w") as file:
                file.write("{}")

        with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
            vault = json.load(file)

        # Overwrite is only True in change mode
        if not overwrite and service_plain in vault:
            # Add mode
            overwrite_message = messagebox.askyesno("Overwrite", f"Content for {service_plain} already exists. Do you want to overwrite it?")
            if not overwrite_message:
                return False

        if rename_service_to_plain:
            # Verify if service exists
            if service_plain in vault:
                vault[rename_service_to_plain] = vault.pop(service_plain)
                service_plain = rename_service_to_plain

        # Save old timestamp
        current_timestamp = vault[service_plain]["timestamp"] if service_plain in vault else int(time.time())
        if prefered_key:
            vault[service_plain] = {
                "username": enc.encrypt_content(username_plain, prefered_key).decode() if username_plain else "",
                "email": enc.encrypt_content(email_plain, prefered_key).decode() if email_plain else "",
                "password": enc.encrypt_content(password_plain, prefered_key).decode(),
                "category": category_plain if category_plain else "",
                "notes": enc.encrypt_content(notes_plain, prefered_key).decode() if notes_plain else "",
                "timestamp": current_timestamp
            }
            with open(f"{os.path.dirname(__file__)}/vault.json", "w") as file:
                json.dump(vault, file)
        else:
            vault[service_plain] = {
                "username": enc.encrypt_content(username_plain, self.key).decode() if username_plain else "",
                "email": enc.encrypt_content(email_plain, self.key).decode() if email_plain else "",
                "password": enc.encrypt_content(password_plain, self.key).decode(),
                "category": category_plain if category_plain else "",
                "notes": enc.encrypt_content(notes_plain, self.key).decode() if notes_plain else "",
                "timestamp": current_timestamp
            }
            with open(f"{os.path.dirname(__file__)}/vault.json", "w") as file:
                json.dump(vault, file)

        # Success
        return True

    def delete_service_content(self, service_plain):
        sure = messagebox.askyesno("Are you sure?", f"Are you sure you want to delete the content for {service_plain}?")
        if not sure:
            return
        with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
            vault = json.load(file)
        if service_plain not in vault:
            messagebox.showerror("Error", f"No content to match {service_plain}")
            return

        del vault[service_plain]
        with open(f"{os.path.dirname(__file__)}/vault.json", "w") as file:
            json.dump(vault, file)
        self.update_password_display()
        self.adjust_window_size()



    # Settings management
    def get_settings(self):
        with open(f"{os.path.dirname(__file__)}/settings.json", "r") as file:
            return json.load(file)

    def update_settings(self, store_key=None, show_passwords=None, backup_dir_paths=None):
        try:
            with open(f"{os.path.dirname(__file__)}/settings.json", "r") as file:
                settings = json.load(file)
        except:
            settings = {"store_key": False, "display_passwords": True, "backup_dir_paths": None}

        if store_key is not None:
            settings["store_key"] = store_key
        if show_passwords is not None:
            settings["display_passwords"] = show_passwords
        if backup_dir_paths is not None:
            if not isinstance(backup_dir_paths, list):
                backup_dir_paths = [backup_dir_paths]
            settings["backup_dir_paths"] = backup_dir_paths
        with open(f"{os.path.dirname(__file__)}/settings.json", "w") as file:
            json.dump(settings, file)

    # UI management
    def update_password_display(self):
        # Inner functions
        def levenshtein_fuzzy_search(query, data, max_distance=5):
            results = {}
            # Check for Levenshtein distance
            for key in data.keys():
                distance = Levenshtein.distance(query, key)
                if distance <= max_distance:
                    results[key] = data[key]

            # Check if query is in the results
            for key in data.keys():
                if query.lower() in key.lower() and key not in results:
                    results[key] = data[key]
            return results

        def copy_password(password):
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()

        def update_scrollbar_visibility():
            # At least 8 items are needed to show scrollbar
            if self.password_display.winfo_height() < self.canvas.winfo_height() or len(all_content) < 8:
                self.scrollbar.pack_forget()
                self.root_scrollbar_visible = False
            else:
                self.scrollbar.pack(side="right", fill="y")
                self.canvas.configure(yscrollcommand=self.scrollbar.set)
                self.root_scrollbar_visible = True

        if not self.password_display:
            return

        # Clear current display
        for widget in self.password_display.winfo_children():
            widget.destroy()

        # Clear password views
        self.password_views = []

        # Get all content
        all_content = self.get_all_service_content(
            self.current_sort,
            self.current_sort_order
        )

        # Search query
        if self.current_search_query and self.current_search_query != "" and self.current_search_query.strip() != "":
            results = levenshtein_fuzzy_search(self.current_search_query, all_content)
            all_content = results

        # Filter by category¸
        if self.current_filter_category and self.current_filter_category != "All":
            filtered_content = {}
            for service, content in all_content.items():
                if self.current_filter_category == "No category" and not content["category"]:
                    filtered_content[service] = content
                if content["category"] == self.current_filter_category:
                    filtered_content[service] = content
            all_content = filtered_content

        # Apply current sorting
        all_content = self.sort_content(
            all_content,
            self.current_sort,
            self.current_sort_order
        )

        # Style
        style = ttk.Style()
        style.configure("TLabel", background="#f0f0f0", foreground="#000000")

        for i, (service, content) in enumerate(all_content.items()):
            username = content["username"]
            email = content["email"]
            password = content["password"]
            category = content["category"]
            notes = content.get("notes", None)

            # Info content frame - service name + category
            info_frame = ttk.Frame(self.password_display)
            info_frame.grid(row=i, column=0, padx=5, pady=5, sticky="w")

            service_name_label = ttk.Label(
                info_frame,
                text=f"{service}",
                font=("Helvetica", 16),
                wraplength=275,
                style="TLabel"
            )
            service_name_label.pack(side="top", fill="x", expand=True)
            category_name_label = ttk.Label(
                info_frame,
                text=f"{category if category else 'No category'}",
                font=("Helvetica", 10),
                wraplength=275
            )
            category_name_label.pack(side="top", fill="x", expand=True)

            # Buttons
            button_frame = tkinter.Frame(self.password_display, bg="#f0f0f0")
            button_frame.grid(row=i, column=1, padx=5, pady=5, sticky="e")
            delete_button = ttk.Button(button_frame, text="Delete", command=lambda s=service: self.delete_service_content(s))
            delete_button.pack(padx=(0, 5), side="right")
            delete_button.bind("<Return>", lambda _, s=service: self.delete_service_content(s))

            view_button = ttk.Button(
                button_frame,
                text="View",
                command=lambda s=service, p=password, u=username, e=email, c=category, n=notes:
                    self.show_password_setter(
                        service_plain=s,
                        password_plain=p,
                        username_plain=u,
                        email_plain=e,
                        category_plain=c,
                        notes_plain=n
                    ),
            )
            view_button.pack(side="right", padx=5)
            view_button.service_name = service
            view_button.bind(
                "<Return>",
                lambda _, s=service, p=password, u=username, e=email, c=category, n=notes:
                    self.show_password_setter(
                        service_plain=s,
                        password_plain=p,
                        username_plain=u,
                        email_plain=e,
                        category_plain=c,
                        notes_plain=n
                    )
            )

            copy_button = ttk.Button(button_frame, text="Copy", command=lambda p=password: copy_password(p))
            copy_button.pack(side="right", padx=5)
            copy_button.bind("<Return>", lambda _, p=password: copy_password(p))

            self.password_views.append(view_button)

        # Update scroll region to match the new content
        self.password_display.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        update_scrollbar_visibility()

    def on_screen_close(self, screen):
        if screen == "root_window":
            self.root_window_open = False
            self.root.destroy()
        elif screen == "password_setter_window":
            self.password_setter_window_open = False
            self.password_setter_window.destroy()
            self.update_password_display()
            # Try to set focus to the view button that was clicked
            try:
                s = self.password_setter_window.current_service
                for view in self.password_views:
                    if view.service_name == s:
                        view.focus_set()
                        break
            except:
                pass
            self.root.lift()
        elif screen == "manage_categories_window":
            self.manage_categories_window_open = False
            self.manage_categories_window.destroy()
            # Additional logic in self.on_manage_categories_window_close
        elif screen == "rename_category_window":
            self.rename_category_window_open = False
            self.rename_category_window.destroy()
            # Additional logic in self.on_rename_category_window_close
        elif screen == "change_master_password_window":
            self.change_master_password_window_open = False
            self.change_master_password_window.destroy()
            self.root.lift()

    def on_screen_open(self, screen):
        if screen == "root_window":
            self.root_window_open = True
        elif screen == "password_setter_window":
            self.password_setter_window_open = True
        elif screen == "manage_categories_window":
            self.manage_categories_window_open = True
        elif screen == "rename_category_window":
            self.rename_category_window_open = True
        elif screen == "change_master_password_window":
            self.change_master_password_window_open = True

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def adjust_window_size(self, window=None):
        target_window = self.root if window is None else window
        target_window.update_idletasks()

        if target_window == self.root:
            self.root.update_idletasks()
            screen_width, screen_height = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            x, y = (screen_width // 2) - (400 // 2), (screen_height // 2) - (500 // 2)
            target_window.geometry(f"850x500+{str(x)}+{str(y)}")
            target_window.maxsize(850, 500)
            target_window.minsize(850, 500)
            return
        elif target_window == self.manage_categories_window:
            self.root.update_idletasks()
            screen_width, screen_height = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            x, y = (screen_width // 2) - (400 // 2), (screen_height // 2) - (500 // 2)
            target_window.geometry(f"400x400+{str(x)}+{str(y)}")
            target_window.maxsize(400, 400)
            target_window.minsize(400, 400)
            return
        else:
            self.root.update_idletasks()
            screen_width, screen_height = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            x, y = (screen_width // 2) - (400 // 2), (screen_height // 2) - (500 // 2)
            window_width = target_window.winfo_reqwidth() + 50
            window_height = target_window.winfo_reqheight() + 50
            x = (screen_width / 2) - (window_width / 2)
            y = (screen_height / 2) - (window_height / 2)
            target_window.geometry(f"{str(window_width)}x{str(window_height)}+{str(x)}+{str(y)}")

    def add_placeholder(self, entry, placeholder_text):
        if not isinstance(entry, tkinter.Entry):
            return
        if entry.get() == "":
            entry.insert(0, placeholder_text)
            entry.configure(foreground="grey")

    def clear_placeholder(self, event):
         if not isinstance(event.widget, tkinter.Entry):
            return
         if event.widget.get() == event.widget.placeholder_text:
            event.widget.delete(0, "end")
            event.widget.configure(foreground="black")

    def restore_placeholder(self, event):
        if not isinstance(event.widget, tkinter.Entry):
            return
        if not event.widget.get():
            event.widget.insert(0, event.widget.placeholder_text)
            event.widget.config(foreground='grey')

    def on_manage_categories_window_close(self, setter_x, setter_y, service=None, password=None, username=None, email=None, category=None, notes=None):
        self.on_screen_close("manage_categories_window")
        self.window_position = (setter_x, setter_y)
        self.manage_categories_window.destroy()
        try:
            self.password_setter_window.destroy()
        except:
            pass
        self.show_password_setter(
            service_plain=service,
            password_plain=password,
            username_plain=username,
            email_plain=email,
            category_plain=category,
            notes_plain=notes
        )
        self.password_setter_window.focus_set()
        self.manage_categories_button.focus_set()
        self.password_setter_window.lift()

    def on_rename_category_window_close(self, service, password, username, email, category, notes):
        self.on_screen_close("rename_category_window")
        self.manage_categories_window.destroy()
        self.show_manage_categories(
            service_r=service,
            password_r=password,
            username_r=username,
            email_r=email,
            category_r=category,
            notes_r=notes
        )
        self.manage_categories_window.focus_set()
        self.manage_categories_window.lift()
        self.new_category_entry.focus_set()

    def on_frame_configure(self, canvas: tkinter.Canvas):
        # Reset the scroll region to encompass the inner frame
        canvas.configure(scrollregion=canvas.bbox("all"))


    # Screens
    def show_initial_screen(self, account_exists=None):
        # Name: self.root (root_window)

        # Check if window is already open and already has a key - logged in
        if self.root_window_open and self.key:
            self.root.lift()
            self.root.focus_set()
            return

        # Set window close event and open status
        self.clear_screen()
        self.root.protocol("WM_DELETE_WINDOW", lambda: self.on_screen_close("root_window"))
        self.root.bind("<Escape>", lambda _: self.on_screen_close("root_window"))
        self.on_screen_open("root_window")

        # Inner functions
        def sign_up_event(store_key, ask_conformation=True):
            # Check if passwords are empty
            if not self.master_password_entry.get() or not self.confirm_password_entry.get():
                messagebox.showerror("Error", "Master password cannot be empty")
                return

            # Check if passwords match
            if self.master_password_entry.get() != self.confirm_password_entry.get():
                messagebox.showerror("Error", "Passwords do not match")
                return

            # Check if any passwords exist
            if ask_conformation:
                with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
                    vault = json.load(file)
                if vault:
                    sure = messagebox.askyesno("Are you sure?", "Are you sure you want to create a new account? Some passwords are already stored, which  will be lost if you proceed.")
                    if not sure:
                        return

            # Update settings and sign up
            self.update_settings(store_key=self.store_key_var_init.get())
            self.sign_up(store_key=store_key)

        def store_key_toggle_init():
            self.store_key_var_init.set(not self.store_key_var_init.get())

        secret_key_exists = self.check_key_presence()
        known_value_exists = self.chcek_known_value_presence()
        if account_exists is None:
            account_exists = secret_key_exists or known_value_exists

        if account_exists:
            # Display login screen
            ttk.Label(self.root, text="Master Password:").pack(pady=10)
            self.password_entry = ttk.Entry(self.root, show="*")
            self.password_entry.pack(pady=5)
            self.password_entry.focus_set()

            # Login button
            login_button = ttk.Button(self.root, text="Login", command= lambda: self.login(store_key=secret_key_exists))
            login_button.pack(pady=5)
            login_button.bind("<Return>", lambda _: self.login(store_key=secret_key_exists))
            self.password_entry.bind("<Return>", lambda _: self.login(store_key=secret_key_exists))
            self.root.bind_class("Button", "<Return>", lambda event: event.widget.invoke())

            # Sign up button
            sign_up_button = ttk.Button(
                self.root,
                text="Sign Up",
                command=lambda: self.show_initial_screen(account_exists=False),
            )
            sign_up_button.pack(side="bottom", pady=5)
            sign_up_button.bind("<Return>", lambda _: self.show_initial_screen(account_exists=False))
        else:
            # Display sign up screen
            # Master password
            ttk.Label(self.root, text="Choose Master Password:").pack(pady=5)
            self.master_password_entry = ttk.Entry(self.root, show="*")
            self.master_password_entry.pack(pady=5)
            self.master_password_entry.focus_set()
            self.master_password_entry.bind("<Return>", lambda _: self.confirm_password_entry.focus_set())

            # Confirm master password
            ttk.Label(self.root, text="Confirm Master Password:").pack(pady=5)
            self.confirm_password_entry = ttk.Entry(self.root, show="*")
            self.confirm_password_entry.pack(pady=5)
            self.confirm_password_entry.bind(
                "<Return>",
                lambda _: sign_up_event(store_key=self.store_key_var_init.get(), ask_conformation=secret_key_exists or known_value_exists)
            )

            # Store key checkbox
            self.store_key_var_init = tkinter.BooleanVar()
            self.store_key_var_init.set(False)
            store_key_checkbox = ttk.Checkbutton(
                self.root,
                text="Store key after closing",
                variable=self.store_key_var_init,
            )
            store_key_checkbox.pack(pady=5)
            store_key_checkbox.bind("<Return>", lambda _: store_key_toggle_init())

            # Sign up button
            sign_up_button = ttk.Button(
                self.root,
                text="Sign Up",
                command=lambda: sign_up_event(store_key=self.store_key_var_init.get(), ask_conformation=secret_key_exists or known_value_exists)
            )
            sign_up_button.pack(pady=5)
            sign_up_button.bind(
                "<Return>",
                lambda _: sign_up_event(store_key=self.store_key_var_init.get(), ask_conformation=secret_key_exists or known_value_exists)
            )

            # Login button
            login_button = ttk.Button(
                self.root,
                text="Login",
                command=lambda: self.show_initial_screen(account_exists=True)
            )
            login_button.pack(side="bottom", pady=5)
            login_button.bind("<Return>", lambda _: self.show_initial_screen(account_exists=True))
            if not secret_key_exists and not known_value_exists:
                login_button.config(state="disabled")

    def show_main_screen(self):
        # Name: self.root (root_window)

        # Set window close event and open status
        self.clear_screen()
        self.root.protocol("WM_DELETE_WINDOW", lambda: self.on_screen_close("root_window"))
        self.on_screen_open("root_window")

        # Inner functions
        def store_key_toggle():
            current_state = self.get_settings()["store_key"]
            new_state = not current_state
            self.store_key_var.set(new_state)
            self.update_settings(store_key=new_state)
            if new_state:
                enc.save_key_to_file(self.key)
                enc.remove_known_value()
            else:
                enc.save_known_value(self.key)
                enc.remove_key_file()

        def show_passwords_toggle():
            self.show_passwords_var.set(not self.show_passwords_var.get())
            self.update_settings(show_passwords=self.show_passwords_var.get())

        def on_search():
            # TODO - performance issue - don't update on every key press
            self.current_search_query = self.search_entry.get()
            self.update_password_display()

        def on_search_enter(event):
            # Perform search on Enter
            self.current_search_query = self.search_entry.get()
            self.update_password_display()
            # Focus on first password view
            try:
                if self.password_views[0]:
                    self.password_views[0].focus_set()
            except IndexError:
                pass

        def on_sort_direction():
            self.current_sort_order = not self.current_sort_order
            self.sort_button.config(text="▲" if self.current_sort_order else "▼")
            self.update_password_display()

        def on_sort_by():
            self.current_sort = sort_dropdown.get()
            self.update_password_display()

        def on_filter():
            self.current_filter_category = category_dropdown.get()
            self.update_password_display()

        settings = self.get_settings()

        # Left side
        color = "#e8e8e8"
        left_frame = tkinter.Frame(self.root, bg=color)
        left_frame.pack(side="left", fill="y")

        # Search option
        search_frame = tkinter.Frame(left_frame, bg=color)
        search_frame.pack(pady=5)
        self.search_entry = ttk.Entry(search_frame, width=25)
        self.search_entry.pack(side="left")
        self.search_entry.placeholder_text = "Search"
        self.add_placeholder(self.search_entry, self.search_entry.placeholder_text)
        self.search_entry.bind("<FocusIn>", self.clear_placeholder)
        self.search_entry.bind("<FocusOut>", self.restore_placeholder)
        # self.search_entry.bind("<KeyRelease>", lambda _: on_search())
        self.search_entry.bind("<Return>", on_search_enter)
        self.search_entry.bind("<Tab>", lambda _: sort_dropdown.focus_set())

        # Sort options
        sort_frame = tkinter.Frame(left_frame, bg=color)
        sort_frame.pack(pady=5)
        tkinter.Label(sort_frame, text="Sort:", bg=color).pack(side="left")
        sort_dropdown = ttk.Combobox(sort_frame, values=["Date", "Name", "Category"], state="readonly", width=10)
        sort_dropdown.current(0)
        sort_dropdown.pack(side="left")
        sort_dropdown.bind("<<ComboboxSelected>>", lambda _: on_sort_by())

        # Sort direction
        self.sort_button = ttk.Button(sort_frame, text="▼", command=on_sort_direction, width=2)
        self.sort_button.pack(side="left")
        self.sort_button.bind("<Return>", lambda _: self.sort_button.invoke())

        # Filter by category
        category_frame = tkinter.Frame(left_frame, bg=color)
        category_frame.pack(pady=5, padx=5)
        tkinter.Label(category_frame, text="Filter by category: ", bg=color).pack(side="left")
        categories = self.get_categories()
        categories.append("No category")
        categories.insert(0, "All")
        category_dropdown = ttk.Combobox(category_frame, values=categories, state="readonly", width=15)
        category_dropdown.current(0)
        category_dropdown.pack(side="left")
        category_dropdown.bind("<<ComboboxSelected>>", lambda _: on_filter())

        # Change master password button
        change_master_password_button = ttk.Button(left_frame, text="Change Master Password", command=self.show_change_master_password)
        change_master_password_button.pack(pady=5, side="bottom")
        change_master_password_button.bind("<Return>", lambda _: change_master_password_button.invoke())

        # Show passwords checkbox - TODO
        # self.show_passwords_var = tkinter.BooleanVar()
        # self.show_passwords_var.set(settings["display_passwords"])
        # show_passwords_checkbox = ttk.Checkbutton(
        #     left_frame,
        #     text="Show passwords",
        #     variable=self.show_passwords_var,
        #     command=lambda: self.update_settings(show_passwords=self.show_passwords_var.get()))
        # show_passwords_checkbox.pack(pady=5, side="bottom")
        # show_passwords_checkbox.bind("<Return>", lambda _: show_passwords_toggle())

        # Store key after closing checkbox
        self.store_key_var = tkinter.BooleanVar()
        self.store_key_var.set(settings["store_key"])
        self.store_key_checkbox = ttk.Checkbutton(
            left_frame,
            text="Store key after closing",
            variable=self.store_key_var,
            command=store_key_toggle,
        )
        style = ttk.Style()
        style.configure("TCheckbutton", background=color)
        self.store_key_checkbox.pack(pady=5, side="bottom")
        self.store_key_checkbox.bind("<Return>", lambda _: store_key_toggle())

        # Right side
        right_frame = tkinter.Frame(self.root, bg="#f0f0f0")
        right_frame.pack(side="right", fill="both", padx=5, pady=5, expand=True, anchor="center")

        # Add password button
        add_password_button = ttk.Button(right_frame, text="Add password", command=self.show_password_setter)
        add_password_button.pack(pady=5)
        add_password_button.bind("<Return>", lambda _: add_password_button.invoke())

        # Canvas for scrollable password display
        self.canvas = tkinter.Canvas(right_frame, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)

        self.scrollbar = ttk.Scrollbar(right_frame, orient="vertical", command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.password_display = tkinter.Frame(self.canvas, bg="#f0f0f0")
        self.canvas.create_window((0, 0), window=self.password_display, anchor='nw')

        self.canvas.bind("<Configure>", lambda _, canvas=self.canvas: self.on_frame_configure(canvas))
        self.password_display.grid_columnconfigure(0, weight=0, minsize=310)

        self.update_password_display()
        self.adjust_window_size()

    def show_password_setter(self, service_plain=None, password_plain=None, username_plain=None, email_plain=None, category_plain=None, notes_plain=None):
        # Name: self.password_setter_window

        # Inner functions
        def submit_content():
            service_plain = service_entry.get()
            password_plain = password_entry.get()
            username_plain = username_entry.get()
            email_plain = email_entry.get()
            category_plain = category_entry.get()
            notes_plain = notes_entry.get("1.0", "end-1c")
            if not service_plain or not password_plain:
                messagebox.showerror("Error", "Service is a required field") if not service_plain else messagebox.showerror("Error", "Password is a required field")
                return
            if change_mode:
                # Check if new name already exists
                if self.get_service_content(service_plain) is not None and service_plain != original_service_plain:
                    messagebox.showerror("Error", f"Service {service_plain} already exists")
                    return
                result = self.save_service_contnet(
                    service_plain=original_service_plain,
                    password_plain=password_plain,
                    username_plain=username_plain if username_plain else "",
                    email_plain=email_plain if email_plain else "",
                    category_plain="" if category_plain == "None" else category_plain,
                    notes_plain=notes_plain if notes_plain else "",
                    overwrite=True,
                    prefered_key=None,
                    rename_service_to_plain=service_plain
                )
            else:
                result = self.save_service_contnet(
                    service_plain=service_plain,
                    password_plain=password_plain,
                    username_plain=username_plain if username_plain else "",
                    email_plain=email_plain if email_plain else "",
                    category_plain="" if category_plain == "None" else category_plain,
                    notes_plain=notes_plain if notes_plain else "",
                    overwrite=False,
                )

            if result:
                self.password_setter_window_open = False
                self.password_setter_window.destroy()
                self.update_password_display()

        # Check if window is already open
        if self.password_setter_window_open and self.password_setter_window and self.password_setter_window.winfo_exists():
            self.password_setter_window.lift()
            self.password_setter_window.focus_set()
            return

        # Set window
        self.password_setter_window = tkinter.Toplevel(self.root)
        self.password_setter_window.grab_set()
        self.password_setter_window.transient(self.root)
        self.password_setter_window.title("Add Password")
        self.password_setter_window.current_service = service_plain

        # Set window close event and open status
        self.password_setter_window.protocol("WM_DELETE_WINDOW", lambda: self.on_screen_close("password_setter_window"))
        self.password_setter_window.bind("<Escape>", lambda _: self.on_screen_close("password_setter_window"))
        self.on_screen_open("password_setter_window")

        change_mode = service_plain is not None and password_plain is not None and self.get_service_content(service_plain) is not None
        original_service_plain = service_plain
        self.password_setter_window.title("Add Password" if not change_mode else "Change Password")
        try:
            self.root.update_idletasks()
            screen_width, screen_height = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            x, y = (screen_width // 2) - (400 // 2), (screen_height // 2) - (500 // 2)
            self.password_setter_window.geometry(f"400x500+{str(x)}+{str(y)}")
        except Exception:
            self.password_setter_window.geometry("400x500+0+0")
            pass

        # Service
        ttk.Label(self.password_setter_window, text="Service*:").pack(pady=1)
        service_entry = ttk.Entry(self.password_setter_window, width=30)
        service_entry.pack(pady=5)
        service_entry.focus_set()
        if service_plain:
            service_entry.insert(0, service_plain)
        service_entry.bind("<Return>", lambda _: submit_content())

        # Password
        ttk.Label(self.password_setter_window, text="Password*:").pack(pady=1)
        password_entry = ttk.Entry(self.password_setter_window, width=50)
        password_entry.pack(pady=5)
        password_entry.bind("<Return>", lambda _: submit_content())
        if password_plain:
            password_entry.insert(0, password_plain)
        password_entry.bind("<Return>", lambda _: submit_content())

        # Username
        ttk.Label(self.password_setter_window, text="Username:").pack(pady=1)
        username_entry = ttk.Entry(self.password_setter_window, width=50)
        username_entry.pack(pady=5)
        username_entry.bind("<Return>", lambda _: submit_content())
        if username_plain:
            username_entry.insert(0, username_plain)

        # Email
        ttk.Label(self.password_setter_window, text="Email:").pack(pady=1)
        email_entry = ttk.Entry(self.password_setter_window, width=50)
        email_entry.pack(pady=5)
        if email_plain:
            email_entry.insert(0, email_plain)
        email_entry.bind("<Return>", lambda _: submit_content())

        # Category
        ttk.Label(self.password_setter_window, text="Category:").pack(pady=1)
        category_frame = ttk.Frame(self.password_setter_window)
        category_frame.pack(pady=5)

        cateories = self.get_categories()
        cateories.insert(0, "None")
        category_entry = ttk.Combobox(category_frame, values=cateories, state="readonly")
        category_entry.current(0)
        category_entry.pack(pady=1, side="left")
        if category_plain:
            # Check if category exists
            if category_plain in cateories:
                category_entry.set(category_plain)
        category_entry.bind("<Return>", lambda _: submit_content())

        # Manage categories button
        self.manage_categories_button = ttk.Button(
            category_frame,
            text="Manage Categories",
            command=lambda: self.show_manage_categories(
                service_r=service_entry.get(),
                password_r=password_entry.get(),
                username_r=username_entry.get(),
                email_r=email_entry.get(),
                category_r=category_entry.get(),
                notes_r=notes_entry.get("1.0", "end-1c")
            )
        )
        self.manage_categories_button.pack(pady=1, side="left")
        self.manage_categories_button.bind("<Return>", lambda _: self.manage_categories_button.invoke())

        # Notes
        ttk.Label(self.password_setter_window, text="Notes:").pack(pady=1)
        notes_entry = ScrolledText(
            self.password_setter_window,
            width=50,
            height=10,
            wrap=tkinter.WORD,
            font=("TkDefaultFont", 9)
        )
        notes_entry.pack(pady=5, padx=10, fill=tkinter.BOTH, expand=True)
        if notes_plain:
            notes_entry.insert(
                tkinter.INSERT,
                notes_plain
            )
        notes_entry.bind("<Tab>", lambda _: save_button.focus_set())
        notes_entry.bind("<Shift-Tab>", lambda _: category_entry.focus_set())

        # Save button
        save_button = ttk.Button(self.password_setter_window, text="Save", command=submit_content)
        save_button.pack(pady=10)
        save_button.bind("<Return>", lambda _: submit_content())

    def show_manage_categories(self, service_r=None, password_r=None, username_r=None, email_r=None, category_r=None, notes_r=None):
        # Name: self.manage_categories_window

        # Check if window is already open
        if self.manage_categories_window_open and self.manage_categories_window and self.manage_categories_window.winfo_exists():
            self.manage_categories_window.lift()
            self.manage_categories_window.focus_set()
            return

        # Set window
        self.manage_categories_window = tkinter.Toplevel(self.root)
        self.manage_categories_window.title("Manage Categories")
        self.manage_categories_window.grab_set()
        self.manage_categories_window.transient(self.root)

        # Set window close event and open status
        self.manage_categories_window.protocol("WM_DELETE_WINDOW", lambda: self.on_manage_categories_window_close(
            self.password_setter_window.winfo_x(), self.password_setter_window.winfo_y(),
            service=service_r, password=password_r, username=username_r, email=email_r, category=category_r, notes=notes_r
        ))
        self.manage_categories_window.bind("<Escape>", lambda _:self.on_manage_categories_window_close(
            self.password_setter_window.winfo_x(), self.password_setter_window.winfo_y(),
            service=service_r, password=password_r, username=username_r, email=email_r, category=category_r, notes=notes_r
        ))
        self.on_screen_open("manage_categories_window")

        # Inner functions
        def add_category():
            category = self.new_category_entry.get()
            if not category or category == self.new_category_entry.placeholder_text:
                messagebox.showerror("Error", "Category cannot be empty")
                try:
                    self.new_category_entry.focus_set()
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

        def delete_category(category):
            self.remove_category(category)
            x = self.manage_categories_window.winfo_x()
            y = self.manage_categories_window.winfo_y()
            self.window_position = (x, y)
            self.manage_categories_window.destroy()
            self.show_manage_categories(
                service_r=service_r, password_r=password_r, username_r=username_r, email_r=email_r, category_r=category_r, notes_r=notes_r
            )

        # Set window position
        self.root.update_idletasks()
        screen_width, screen_height = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = (screen_width // 2) - (400 // 2) + 30, (screen_height // 2) - (500 // 2) + 30
        self.manage_categories_window.geometry(f"400x400+{str(x)}+{str(y)}")
        self.manage_categories_window.maxsize(400, 400)
        self.manage_categories_window.minsize(400, 400)

        # Scrollable frame
        self.c_scroll_frame = ttk.Frame(self.manage_categories_window, height=100)
        self.c_scroll_frame.pack(fill="x", side="top")

        self.c_canvas = tkinter.Canvas(self.c_scroll_frame, height=300, highlightthickness=0)
        self.c_canvas.pack(side="left", fill="both", expand=True)

        self.c_scrollbar = ttk.Scrollbar(self.c_scroll_frame, orient="vertical", command=self.c_canvas.yview)
        self.c_scrollbar.pack(side="right", fill="y")
        self.c_canvas.configure(yscrollcommand=self.c_scrollbar.set)

        self.manage_categories_frame = ttk.Frame(self.c_canvas)
        self.manage_categories_frame.bind("<Configure>", lambda _, canvas=self.c_canvas: self.on_frame_configure(canvas))
        self.c_canvas.create_window((0, 0), window=self.manage_categories_frame, anchor="nw")
        self.manage_categories_frame.grid_columnconfigure(0, weight=1, minsize=210)

        categories = self.get_categories()
        for i, category in enumerate(categories):
            # Category name frame
            cateogry_name_frame = ttk.Frame(self.manage_categories_frame)
            cateogry_name_frame.grid(row=i, column=0, padx=5, pady=5, sticky="w")

            category_name_label = ttk.Label(cateogry_name_frame, text=category, wraplength=200)
            category_name_label.pack(side="left", fill="x", expand=True, padx=5)

            # Buttons
            button_frame = ttk.Frame(self.manage_categories_frame)
            button_frame.grid(row=i, column=1, padx=5, pady=5, sticky="e")

            delete_button = ttk.Button(button_frame, text="Delete", command=lambda c=category: delete_category(c))
            delete_button.pack(side="right")
            delete_button.bind("<Return>", lambda _, c=category: delete_category(c))

            change_button = ttk.Button(
                button_frame,
                text="Rename",
                command=lambda c=category: self.show_rename_category(category=c, service_r=service_r, password_r=password_r, username_r=username_r, email_r=email_r, category_r=category_r, notes_r=notes_r)
            )
            change_button.pack(side="right")
            change_button.bind(
                "<Return>",
                lambda _, c=category: self.show_rename_category(category=c, service_r=service_r, password_r=password_r, username_r=username_r, email_r=email_r, category_r=category_r, notes_r=notes_r)
            )


        # Add category entry
        self.new_category_entry = ttk.Entry(self.manage_categories_window, width=50)
        self.new_category_entry.pack(pady=5)
        self.new_category_entry.focus_set()
        self.new_category_entry.placeholder_text = "Add new category"
        self.add_placeholder(self.new_category_entry, self.new_category_entry.placeholder_text)
        self.manage_categories_window.bind("<FocusIn>", self.clear_placeholder)
        self.manage_categories_window.bind("<FocusOut>", self.restore_placeholder)
        self.new_category_entry.bind("<Return>", lambda _: add_category())


        # Add category button
        add_category_button = ttk.Button(self.manage_categories_window, text="Add Category", command=add_category)
        add_category_button.pack(pady=10)
        add_category_button.bind("<Return>", lambda _: add_category())

        self.adjust_window_size(self.manage_categories_window)
        self.new_category_entry.focus_set()

    def show_rename_category(self, category, service_r=None, password_r=None, username_r=None, email_r=None, category_r=None, notes_r=None):
        # Name: self.rename_category_window

        # Check if window is already open
        if self.rename_category_window_open and self.rename_category_window and self.rename_category_window.winfo_exists():
            self.rename_category_window.lift()
            self.rename_category_window.focus_set()
            return

        # Set window
        self.rename_category_window = tkinter.Toplevel(self.root)
        self.rename_category_window.title("Rename Category")
        self.root.update_idletasks()
        screen_width, screen_height = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = (screen_width // 2) - (400 // 2) + 30, (screen_height // 2) - (500 // 2) + 30
        self.rename_category_window.geometry(f"400x200+{str(x)}+{str(y)}")
        self.rename_category_window.maxsize(400, 200)
        self.rename_category_window.minsize(400, 200)
        self.rename_category_window.grab_set()
        self.rename_category_window.transient(self.root)

        # Set window close event and open status
        self.rename_category_window.protocol("WM_DELETE_WINDOW", lambda: self.on_rename_category_window_close(
            service=service_r, password=password_r, username=username_r, email=email_r, category=category_r, notes=notes_r
        ))
        self.rename_category_window.bind("<Escape>", lambda _: self.on_rename_category_window_close(
            service=service_r, password=password_r, username=username_r, email=email_r, category=category_r, notes=notes_r
        ))
        self.on_screen_open("rename_category_window")

        # Inner functions
        def rename_category():
            x = self.manage_categories_window.winfo_x()
            y = self.manage_categories_window.winfo_y()
            self.window_position = (x, y)
            new_category = category_entry.get()
            if not new_category:
                messagebox.showerror("Error", "Category name cannot be empty")
                return
            if new_category == category:
                self.rename_category_window.destroy()
                self.manage_categories_window.destroy()
                self.show_manage_categories(
                    service_r=service_r, password_r=password_r, username_r=username_r, email_r=email_r, category_r=new_category, notes_r=notes_r
                )
                return

            if self.rename_category(category, new_category):
                # Get current window position
                self.rename_category_window.destroy()
                self.manage_categories_window.destroy()
                self.show_manage_categories(
                    service_r=service_r, password_r=password_r, username_r=username_r, email_r=email_r, category_r=new_category, notes_r=notes_r
                )
                return

        ttk.Label(self.rename_category_window, text="Category name:").pack(pady=10)
        category_entry = ttk.Entry(self.rename_category_window, width=50)
        category_entry.pack(pady=5)
        category_entry.insert(0, category)
        category_entry.focus_set()
        category_entry.bind("<Return>", lambda _: rename_category())

        rename_category_button = ttk.Button(self.rename_category_window, text="Rename Category", command=rename_category)
        rename_category_button.pack(pady=10)
        rename_category_button.bind("<Return>", lambda _: rename_category())

    def show_change_master_password(self):
        # Name: self.change_master_password_window

        # Check if window is already open
        if self.change_master_password_window_open and self.change_master_password_window and self.change_master_password_window.winfo_exists():
            self.change_master_password_window.lift()
            self.change_master_password_window.focus_set()
            return

        # Set window
        self.change_master_password_window = tkinter.Toplevel(self.root)
        self.change_master_password_window.title("Change Master Password")
        self.root.update_idletasks()
        screen_width, screen_height = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = (screen_width // 2) - (400 // 2) + 30, (screen_height // 2) - (500 // 2) + 30
        self.change_master_password_window.geometry(f"300x200+{str(x)}+{str(y)}")

        # Set window close event and open status
        self.change_master_password_window.protocol("WM_DELETE_WINDOW", lambda: self.on_screen_close("change_master_password_window"))
        self.change_master_password_window.bind("<Escape>", lambda _: self.on_screen_close("change_master_password_window"))
        self.on_screen_open("change_master_password_window")
        self.change_master_password_window.grab_set()
        self.change_master_password_window.transient(self.root)

        # Inner functions
        def change_master_password():
            old_password = old_password_entry.get()
            current_store_key_setting = self.get_settings()["store_key"]

            # Verify old master password is not empty
            if not old_password or old_password == old_password_entry.placeholder_text:
                messagebox.showerror("Error", "Old master password cannot be empty")
                return

            # Verify old master password
            if current_store_key_setting:
                # Verify old master password with stored key
                if not enc.verify_password_with_stored_key(old_password):
                    messagebox.showerror("Error", "Invalid old master password")
                    return
            else:
                # Verify old master password without stored key
                if not enc.verify_password_without_stored_key(old_password):
                    messagebox.showerror("Error", "Invalid old master password")
                    return

            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()
            # Verify new master password is not empty
            if not new_password or not confirm_password or new_password == new_password_entry.placeholder_text or confirm_password == confirm_password_entry.placeholder_text:
                messagebox.showerror("Error", "New master password cannot be empty")
                return

            if new_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return

            if new_password == old_password:
                messagebox.showerror("Error", "New password cannot be the same as the old password")
                return

            sure = messagebox.askyesno("Are you sure?", "Are you sure you want to change the master password?")
            if not sure:
                return

            # Setup new master password and encrypt current content with new key
            new_key = enc.setup_master_password(new_password, current_store_key_setting)
            new_vault = {}
            with open(f"{os.path.dirname(__file__)}/vault.json", "r") as file:
                vault = json.load(file)
            for service, content in vault.items():
                new_content = {}
                for key, value in content.items():
                    # Skip empty values
                    if not value:
                        new_content[key] = value
                        continue
                    # Skip category and timestamp - not encrypted
                    if key in ["category", "timestamp"]:
                        new_content[key] = value
                        continue
                    # Decrypt the old content and encrypt with new key
                    value_plain = enc.decrypt_content(value, self.key)
                    if not value_plain:
                        # Decryption failed
                        raise DecryptionError(f"Decryption failed for {service} - {key}")
                    new_content[key] = enc.encrypt_content(value_plain, new_key).decode()

                new_vault[service] = new_content

            with open(f"{os.path.dirname(__file__)}/vault.json", "w") as file:
                json.dump(new_vault, file)

            # Change key
            self.key = new_key
            self.change_master_password_window.destroy()

        old_password_entry = ttk.Entry(self.change_master_password_window, width=40)
        old_password_entry.placeholder_text = "Old master password"
        self.add_placeholder(old_password_entry, old_password_entry.placeholder_text)
        old_password_entry.bind("<FocusIn>", self.clear_placeholder)
        old_password_entry.bind("<FocusOut>", self.restore_placeholder)
        old_password_entry.bind("<Return>", lambda _: new_password_entry.focus_set())
        old_password_entry.pack(pady=5)
        old_password_entry.focus_set()

        new_password_entry = ttk.Entry(self.change_master_password_window, width=40)
        new_password_entry.placeholder_text = "New master password"
        self.add_placeholder(new_password_entry, new_password_entry.placeholder_text)
        new_password_entry.bind("<FocusIn>", self.clear_placeholder)
        new_password_entry.bind("<FocusOut>", self.restore_placeholder)
        new_password_entry.bind("<Return>", lambda _: confirm_password_entry.focus_set())
        new_password_entry.pack(pady=5)

        confirm_password_entry = ttk.Entry(self.change_master_password_window, width=40)
        confirm_password_entry.placeholder_text = "Confirm new master password"
        self.add_placeholder(confirm_password_entry, confirm_password_entry.placeholder_text)
        confirm_password_entry.bind("<FocusIn>", self.clear_placeholder)
        confirm_password_entry.bind("<FocusOut>", self.restore_placeholder)
        confirm_password_entry.pack(pady=5)
        confirm_password_entry.bind("<Return>", lambda _: change_master_password())

        change_password_button = ttk.Button(self.change_master_password_window, text="Change Master Password", command=change_master_password)
        change_password_button.pack(pady=10)
        change_password_button.bind("<Return>", lambda _: change_master_password())

def main():
    def exit_app(app_instance: PasswordManagerApp):
        if app_instance is None or not app_instance.key:
            return
        # Remove key file if store key is not enabled
        try:
            settings = app_instance.get_settings()
            if settings["store_key"]:
                # Save key file and remove known value file
                enc.save_key_to_file(app_instance.key)
                enc.remove_known_value()
            else:
                # Save known value file and remove key file
                enc.save_known_value(app_instance.key)
                enc.remove_key_file()

            # Backup
            app_instance.backup_files()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    # Key binding methods
    def control_f():
        try:
            # If already focused on search entry, empty search entry
            if app_instance.search_entry.focus_get() == app_instance.search_entry:
                app_instance.search_entry.delete(0, tkinter.END)
                app_instance.search_entry.focus_set()
            else:
                app_instance.search_entry.focus_set()
        except:
            pass
    def control_n():
        try:
            app_instance.show_password_setter()
        except:
            pass
    def focus_password_view(index):
        if not app_instance.password_views:
            return

        # If focused on search entry, don't change focus - typing priority
        if app_instance.search_entry.focus_get() == app_instance.search_entry:
            return

        try:
            index = int(index) - 1
            if 0 <= index < len(app_instance.password_views):
                app_instance.password_views[index].focus_set()
            else:
                app_instance.password_views[-1].focus_set()
        except:
            pass
    def scroll(event):
        try:
            if event.type == tkinter.EventType.MouseWheel:
                scroll_units = -1 * (event.delta // 120)
            elif event.type == tkinter.EventType.KeyPress and event.keysym == 'Down':
                scroll_units = 1
            elif event.type == tkinter.EventType.KeyPress and event.keysym == 'Up':
                scroll_units = -1
            else:
                return

            if app_instance.root_window_open:
                # Check if only main root window is open
                if not (
                    app_instance.password_setter_window_open or
                    app_instance.manage_categories_window_open or
                    app_instance.rename_category_window_open or
                    app_instance.change_master_password_window_open
                ) and app_instance.root_scrollbar_visible:
                    app_instance.canvas.yview_scroll(scroll_units, "units")
                    return
            if app_instance.manage_categories_window_open:
                # Check if only manage categories and root window are open
                if (
                    app_instance.password_setter_window_open and
                    not app_instance.rename_category_window_open and
                    not app_instance.change_master_password_window_open
                ):
                    app_instance.c_canvas.yview_scroll(scroll_units, "units")
        except:
            pass

    app_instance = None
    try:
        root = ThemedTk(theme="arc")
        root.configure(bg="#f0f0f0")
        app_instance = PasswordManagerApp(root)
        # Set window title
        root.title("Password Manager")

        # Set geometry
        root.update_idletasks()
        screen_width, screen_height = root.winfo_screenwidth(), root.winfo_screenheight()
        x, y = (screen_width // 2) - (400 // 2) + 30, (screen_height // 2) - (500 // 2) + 30
        root.geometry(f"300x300+{str(x)}+{str(y)}")
        root.lift()

        # Set icon
        root.iconphoto(True, tkinter.PhotoImage(file=f"{os.path.dirname(__file__)}/icon.png"))

        # Key bindings
        root.bind("<Control-f>", lambda _: control_f())
        root.bind("<Control-n>", lambda _: control_n())
        for i in range(10):
            root.bind(f"{i}", lambda e, i=i: focus_password_view(i))
        root.bind_all("<MouseWheel>", lambda event: scroll(event))
        root.bind_all("<Down>", lambda event: scroll(event))
        root.bind_all("<Up>", lambda event: scroll(event))

        root.mainloop()
    except FileExistsError as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        if app_instance:
            exit_app(app_instance)
    finally:
        if app_instance:
            exit_app(app_instance)

if __name__ == "__main__":
    try:
        me = singleton.SingleInstance()
        main()
    except singleton.SingleInstanceException:
        sys.exit(0)
