from cryptography.fernet import Fernet
import os
import getpass
import re
import random
import string
import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, ttk
from PIL import Image, ImageTk

# Store Key file
KEY_FILE = "secret.key"
DATABASE_FILE = "passwords.db"

class PasswordManager:
    def __init__(self):
        self.key = self.load_key()
        self.create_table()
        self.master_password = os.getenv('MASTER_PASSWORD', 'oshada2005')

    # Generate/Load encryption key
    def load_key(self):
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as key_file:
                key_file.write(key)
            return key

    # Create database table
    def create_table(self):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    # Encrypt and Decrypt functions
    def encrypt_message(self, message):
        f = Fernet(self.key)
        return f.encrypt(message.encode())

    def decrypt_message(self, encrypted_message):
        f = Fernet(self.key)
        return f.decrypt(encrypted_message).decode()

    # Password Strength Checker
    def check_password_strength(self, password):
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):  # At least one uppercase letter
            return False
        if not re.search(r"[0-9]", password):  # At least one digit
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # At least one special character
            return False
        return True

    # Password Generator
    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    # Save account info
    def add_account(self, service_name, username, password):
        if not self.check_password_strength(password):
            return "Password is too weak. Please use a stronger password!"
        
        encrypted_username = self.encrypt_message(username)
        encrypted_password = self.encrypt_message(password)

        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO accounts (service, username, password) VALUES (?, ?, ?)',
                       (service_name, encrypted_username.decode(), encrypted_password.decode()))
        conn.commit()
        conn.close()
        return f"Account for {service_name} added successfully!"

    # View all stored accounts
    def view_accounts(self):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT service, username, password FROM accounts')
        rows = cursor.fetchall()
        conn.close()
        
        if rows:
            result = "Stored Accounts:\n"
            for row in rows:
                service, encrypted_username, encrypted_password = row
                decrypted_username = self.decrypt_message(encrypted_username.encode())
                decrypted_password = self.decrypt_message(encrypted_password.encode())
                result += f"Service: {service}\nUsername: {decrypted_username}\nPassword: {decrypted_password}\n\n"
            return result
        else:
            return "No any stored accounts yet!"

    # Search for the account
    def search_account(self, search_term):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT service, username, password FROM accounts WHERE service LIKE ? OR username LIKE ?',
                       (f'%{search_term}%', f'%{search_term}%'))
        rows = cursor.fetchall()
        conn.close()

        if rows:
            result = "Search Results:\n"
            for row in rows:
                service, encrypted_username, encrypted_password = row
                decrypted_username = self.decrypt_message(encrypted_username.encode())
                decrypted_password = self.decrypt_message(encrypted_password.encode())
                result += f"Service: {service}\nUsername: {decrypted_username}\nPassword: {decrypted_password}\n\n"
            return result
        else:
            return f"No account found for '{search_term}'"

    # Edit an account
    def edit_account(self, service_name, new_username=None, new_password=None):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()

        cursor.execute('SELECT username, password FROM accounts WHERE service = ?', (service_name,))
        row = cursor.fetchone()

        if row:
            current_username, current_password = row
            if new_username:
                current_username = new_username
            if new_password:
                if not self.check_password_strength(new_password):
                    return "New password is too weak. Please use a stronger password!"
                current_password = new_password

            encrypted_username = self.encrypt_message(current_username).decode()
            encrypted_password = self.encrypt_message(current_password).decode()

            cursor.execute('UPDATE accounts SET username = ?, password = ? WHERE service = ?',
                           (encrypted_username, encrypted_password, service_name))
            conn.commit()
            return f"Account for {service_name} updated successfully!"
        else:
            return f"No account found for '{service_name}'"
        
        conn.close()

    # Delete an account
    def delete_account(self, service_name):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM accounts WHERE service = ?', (service_name,))
        if cursor.rowcount > 0:
            conn.commit()
            return f"Account for {service_name} deleted successfully!"
        else:
            return f"No account found for '{service_name}'"
        
        conn.close()

# GUI Class
class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Password Manager by Oshada Rashmika")
        self.pm = PasswordManager()
        
        # Authenticate User
        self.authenticate_user()

    # Authentication Window
    def authenticate_user(self):
        self.auth_window = tk.Toplevel(self.root)
        self.auth_window.title("User Authentication")
        self.auth_window.geometry("300x150")
        self.auth_window.configure(bg="#3A3F47")

        tk.Label(self.auth_window, text="Enter Password to Access:", font=("Sansation", 14), bg="#3A3F47", fg="#FFFFFF").pack(pady=20)
        self.password_entry = tk.Entry(self.auth_window, show='*', font=("Sansation", 14))
        self.password_entry.pack(pady=5)

        tk.Button(self.auth_window, text="Access", command=self.check_password, bg="#ff3f3f", fg="#FFFFFF").pack(pady=10)

    # Check if Master Password is correct or incorrect
    def check_password(self):
        entered_password = self.password_entry.get()
        if entered_password == self.pm.master_password:
            self.auth_window.destroy()
            self.create_widgets()
        else:
            messagebox.showerror("Access Denied!", "Incorrect Master Password.")

    def create_widgets(self):
        # Theme setting
        self.root.configure(bg="#3A3F47")
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Sansation', 12), padding=10, relief='flat')
        self.style.map('TButton', background=[('active', '#3A3F47')])  # Change button color on hover
        self.style.configure('TLabel', font=('Sansation', 14, 'bold'), background="#3A3F47", foreground="#FFFFFF")

        # Title
        title_label = tk.Label(self.root, text="Password Manager by Oshada Rashmika", font=("Sansation", 24, 'bold', 'italic'), bg="#3A3F47", fg="#FFFFFF")
        title_label.pack(pady=20)

        # Text Area for Displaying Results
        self.result_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=60, height=20, font=('Sansation', 12, 'italic'), bg="#333333", fg="#FFFFFF", borderwidth=2, relief="flat")
        self.result_area.pack(pady=20)

        # Button Frame
        button_frame = tk.Frame(self.root, bg="#3A3F47")
        button_frame.pack(pady=10)

        # Button Images
        add_icon = ImageTk.PhotoImage(Image.open(r"C:\Users\user\Documents\Python projects\Password Manager\add.png").resize((20, 20), Image.LANCZOS))
        view_icon = ImageTk.PhotoImage(Image.open(r"C:\Users\user\Documents\Python projects\Password Manager\view.png").resize((20, 20), Image.LANCZOS))
        search_icon = ImageTk.PhotoImage(Image.open(r"C:\Users\user\Documents\Python projects\Password Manager\search.png").resize((20, 20), Image.LANCZOS))
        edit_icon = ImageTk.PhotoImage(Image.open(r"C:\Users\user\Documents\Python projects\Password Manager\edit.png").resize((20, 20), Image.LANCZOS))
        delete_icon = ImageTk.PhotoImage(Image.open(r"C:\Users\user\Documents\Python projects\Password Manager\delete.png").resize((20, 20), Image.LANCZOS))
        generate_icon = ImageTk.PhotoImage(Image.open(r"C:\Users\user\Documents\Python projects\Password Manager\generate.png").resize((20, 20), Image.LANCZOS))
        exit_icon = ImageTk.PhotoImage(Image.open(r"C:\Users\user\Documents\Python projects\Password Manager\exit.png").resize((20, 20), Image.LANCZOS))

        # Add Account Button
        add_button = ttk.Button(button_frame, image=add_icon, text="Add", command=self.add_account, compound=tk.TOP)
        add_button.grid(row=0, column=0, padx=5)
        add_button.image = add_icon

        # View Accounts Button
        view_button = ttk.Button(button_frame, image=view_icon, text="View", command=self.view_accounts, compound=tk.TOP)
        view_button.grid(row=0, column=1, padx=5)
        view_button.image = view_icon

        # Search Account Button
        search_button = ttk.Button(button_frame, image=search_icon, text="Search", command=self.search_account, compound=tk.TOP)
        search_button.grid(row=0, column=2, padx=5)
        search_button.image = search_icon

        # Edit Account Button
        edit_button = ttk.Button(button_frame, image=edit_icon, text="Edit", command=self.edit_account, compound=tk.TOP)
        edit_button.grid(row=0, column=3, padx=5)
        edit_button.image = edit_icon

        # Delete Account Button
        delete_button = ttk.Button(button_frame, image=delete_icon, text="Delete", command=self.delete_account, compound=tk.TOP)
        delete_button.grid(row=0, column=4, padx=5)
        delete_button.image = delete_icon

        # Generate Password Button
        generate_button = ttk.Button(button_frame, image=generate_icon, text="Generate", command=self.generate_password, compound=tk.TOP)
        generate_button.grid(row=0, column=5, padx=5)
        generate_button.image = generate_icon

        # Exit Button
        exit_button = ttk.Button(button_frame, image=exit_icon, text="Exit", command=self.root.quit, compound=tk.TOP)
        exit_button.grid(row=0, column=6, padx=5)
        exit_button.image = exit_icon

    # Button Command Methods
    def add_account(self):
        service_name = simpledialog.askstring("Service/App Name", "Enter service/app name:")
        username = simpledialog.askstring("Username", "Enter username:")
        password = simpledialog.askstring("Password", "Enter password:")
        result = self.pm.add_account(service_name, username, password)
        self.result_area.insert(tk.END, result + "\n")

    def view_accounts(self):
        result = self.pm.view_accounts()
        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, result)

    def search_account(self):
        search_term = simpledialog.askstring("Search", "Enter service/app name or username to search:")
        result = self.pm.search_account(search_term)
        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, result)

    def edit_account(self):
        service_name = simpledialog.askstring("Service/App Name", "Enter service/app name to edit:")
        new_username = simpledialog.askstring("New Username", "Enter new username (leave blank to keep current):")
        new_password = simpledialog.askstring("New Password", "Enter new password (leave blank to keep current):")
        result = self.pm.edit_account(service_name, new_username, new_password)
        self.result_area.insert(tk.END, result + "\n")

    def delete_account(self):
        service_name = simpledialog.askstring("Service/App Name", "Enter service/app name to delete:")
        result = self.pm.delete_account(service_name)
        self.result_area.insert(tk.END, result + "\n")

    def generate_password(self):
        password = self.pm.generate_password()
        self.result_area.insert(tk.END, f"Generated Password: {password}\n")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.geometry("1920x1080")
    root.mainloop()















