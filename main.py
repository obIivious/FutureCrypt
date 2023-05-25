import os
import base64
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
import tarfile
from cryptography.fernet import Fernet
import shutil

class FileEncryptorDecryptor:
    def __init__(self, key):
        self.key = key
        self.fernet = Fernet(self.key)

    def encrypt_directory(self, directory_path):
        # Create the encrypted file path
        encrypted_file_path = directory_path + '.fce'

        # Compress the directory into a single file
        self.compress_directory(directory_path, encrypted_file_path)

        # Encrypt the compressed file
        self.encrypt_file(encrypted_file_path)

        # Remove the original directory
        shutil.rmtree(directory_path)

    def compress_directory(self, directory_path, compressed_file_path):
        with tarfile.open(compressed_file_path, 'w:gz') as tar:
            tar.add(directory_path, arcname=os.path.basename(directory_path))

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            data = file.read()

        encrypted_data = self.fernet.encrypt(data)

        with open(file_path, 'wb') as file:
            file.write(encrypted_data)

    def decrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            data = file.read()

        decrypted_data = self.fernet.decrypt(data)

        with open(file_path, 'wb') as file:
            file.write(decrypted_data)

    def decrypt_directory(self, encrypted_file_path):
        # Create the decrypted directory path
        decrypted_directory_path = encrypted_file_path[:-4]  # Remove the '.fce' extension

        # Decrypt the encrypted file
        self.decrypt_file(encrypted_file_path)

        # Extract the compressed file to the decrypted directory
        self.extract_directory(encrypted_file_path, decrypted_directory_path)

        # Remove the encrypted file
        os.remove(encrypted_file_path)

    def extract_directory(self, compressed_file_path, target_directory):
        with tarfile.open(compressed_file_path, 'r:gz') as tar:
            tar.extractall(path=target_directory)


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("FutureCrypt")
        self.root.geometry("350x250")

        self.password_entry = None
        self.encryptor_decryptor = None

        self.create_widgets()

    def create_widgets(self):
        # Password label and entry
        self.password_label = tk.Label(self.root, text="Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(self.root, show='*')
        self.password_entry.pack()

        # Encrypt button
        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_directory)
        self.encrypt_button.pack()

        # Decrypt button
        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_directory)
        self.decrypt_button.pack()

    def encrypt_directory(self):
        password = self.password_entry.get()
        if not password:
            self.show_message("Please enter a password.")
            return

        directory_path = filedialog.askdirectory()
        if directory_path:
            self.encryptor_decryptor = FileEncryptorDecryptor(self.generate_key(password))
            self.encryptor_decryptor.encrypt_directory(directory_path)
            self.show_message("Encryption completed.")

    def decrypt_directory(self):
        password = self.password_entry.get()
        if not password:
            self.show_message("Please enter a password.")
            return

        file_path = filedialog.askopenfilename(filetypes=[("FutureCrypt Files", ".fce")])
        if file_path:
            self.encryptor_decryptor = FileEncryptorDecryptor(self.generate_key(password))
            self.encryptor_decryptor.decrypt_directory(file_path)
            self.show_message("Decryption completed.")

    def generate_key(self, password):
        # Generate a 32-byte key from the password
        key = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(key)

    def show_message(self, message):
        messagebox.showinfo("Message", message)


root = tk.Tk()
app = App(root)
root.mainloop()
