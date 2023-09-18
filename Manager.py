import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import random
import string
import os
from cryptography.fernet import Fernet
import json

class Application:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")

        self.login_data = {}
        self.encryption_key = self.load_or_generate_encryption_key()

        self.load_login_data("login_data.json")

        self.create_widgets()

        self.failed_attempts = 0

    def load_or_generate_encryption_key(self):
        key_file = "encryption_key.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as file:
                return file.read()
        else:
            new_key = Fernet.generate_key()
            with open(key_file, "wb") as file:
                file.write(new_key)
            return new_key

    def encrypt_data(self, data):
        cipher_suite = Fernet(self.encryption_key)
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data):
        cipher_suite = Fernet(self.encryption_key)
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return decrypted_data.decode()

    def save_encrypted_data(self, filename, data):
        with open(filename, "wb") as file:
            encrypted_data = self.encrypt_data(data)
            file.write(encrypted_data)

    def load_encrypted_data(self, filename):
        try:
            with open(filename, "rb") as file:
                encrypted_data = file.read()
                return self.decrypt_data(encrypted_data)
        except FileNotFoundError:
            return None

    def create_widgets(self):
        self.label = tk.Label(self.root, text="Password Manager", padx=10, pady=10)
        self.label.pack()

        self.generate_button = tk.Button(self.root, text="Generate Password", command=self.generate_password)
        self.display_button = tk.Button(self.root, text="Display Login Data", command=self.display_login_data)
        self.reset_button = tk.Button(self.root, text="Reset Access Key", command=self.reset_encryption_key)
        self.exit_button = tk.Button(self.root, text="Exit", command=self.root.quit)

        self.generate_button.pack()
        self.display_button.pack()
        self.reset_button.pack()
        self.exit_button.pack()

        self.terminal_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=10, width=50)
        self.terminal_text.pack()

    def display_output(self, output):
        self.terminal_text.insert(tk.END, output + "\n")
        self.terminal_text.see(tk.END)

    def generate_password(self):
        password_length = simpledialog.askinteger("Password Length", "Enter password length (between 8 and 128):", minvalue=8, maxvalue=128)
        if password_length is not None:
            include_special = messagebox.askyesno("Include Special Characters", "Do you want to include special characters to improve security?")
            characters = string.ascii_letters + string.digits
            if include_special:
                characters += string.punctuation
            password = ''.join(random.choice(characters) for _ in range(password_length))

            name_password = simpledialog.askstring("Enter a Name", "Enter a name for the password:")
            if name_password is not None:
                self.login_data[name_password] = password
                self.display_output(f"Generated Password: {password} (Named as '{name_password}')")
            else:
                self.display_output(f"Generated Password: {password}")

    def display_login_data(self):
        if self.encryption_key is None:
            self.display_output("Access denied. No encryption key found.")
            self.failed_attempts += 1
            if self.failed_attempts >= 5:
                self.failed_attempts = 0
                self.delete_login_data()
                if not os.path.exists("login_data.json"):
                    self.display_output("Max failed attempts reached. Login data deleted. Please generate a new access key.")
                    self.reset_encryption_key()
        else:
            self.display_output("Login Data:")
            for login_name, password in self.login_data.items():
                self.display_output(f"Login: {login_name}, Password: {password}")

    def reset_encryption_key(self):
        confirm_reset = messagebox.askyesno("Confirm Reset", "Are you sure you want to reset the encryption key?\nThis will delete stored login data.")
        if confirm_reset:
            key_file = "encryption_key.key"
            self.delete_login_data()
        
            # Generate a new encryption key
            new_encryption_key = Fernet.generate_key()

            # Write the new encryption key to the key file
            with open(key_file, "wb") as file:
                file.write(new_encryption_key)

            self.encryption_key = new_encryption_key

            new_key_message = f"Access key reset. New encryption key generated and saved."
            self.display_output(new_key_message)

    def delete_login_data(self):
        try:
            os.remove("login_data.enc")
            self.login_data.clear()
            self.display_output("Login data deleted.")
        except FileNotFoundError:
            pass

    def save_login_data(self, filename):
        with open(filename, "w") as file:
            json.dump(self.login_data, file)

    def load_login_data(self, filename):
        try:
            with open(filename, "r") as file:
                self.login_data = json.load(file)
        except FileNotFoundError:
            self.login_data = {}

    def main(self):
        self.display_output("Password Manager V 1.0 - use reset access key to generate a key")
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    app.main()

app.save_login_data("login_data.json")