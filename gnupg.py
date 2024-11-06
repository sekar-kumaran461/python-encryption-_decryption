import tkinter as tk
import gnupg
from tkinter import filedialog, messagebox

class GnuPGApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GnuPG Text Encryption & Decryption")
        self.root.geometry("1000x800")
        
        self.gpg = gnupg.GPG()

        # Background color
        self.root.config(bg="#2b2b2b")

        # Container Frame
        self.container = tk.Frame(self.root, bg="#3e3e3e", bd=2, relief=tk.RAISED)
        self.container.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=800, height=600)

        # Title
        self.title_label = tk.Label(self.container, text="GnuPG Text Encryption", font=("Arial", 22, "bold"), bg="#3e3e3e", fg="white")
        self.title_label.pack(pady=10)

        # Description
        self.description_label = tk.Label(self.container, text="This page encrypts and decrypts text data using GnuPG.", font=("Arial", 18), bg="#3e3e3e", fg="white")
        self.description_label.pack(pady=20)

        # Upload text file button
        self.upload_button = tk.Button(self.container, text="Upload Text File", command=self.upload_text_file, width=30, bg="#5a9", fg="white")
        self.upload_button.pack(pady=10)

        # Encrypt button
        self.encrypt_button = tk.Button(self.container, text="Encrypt Text", command=self.encrypt_text, width=30, bg="#5a9", fg="white")
        self.encrypt_button.pack(pady=10)

        # Decrypt button
        self.decrypt_button = tk.Button(self.container, text="Decrypt Text", command=self.decrypt_text, width=30, bg="#5a9", fg="white")
        self.decrypt_button.pack(pady=10)

        self.filepath = ""

    def upload_text_file(self):
        self.filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.filepath:
            messagebox.showinfo("Selected", f"Selected file: {self.filepath}")

    def encrypt_text(self):
        if self.filepath:
            with open(self.filepath, 'r') as file:
                plaintext = file.read()
            encrypted_data = self.gpg.encrypt(plaintext, recipients=None, symmetric=True)
            with open('gnupg_encrypted_text.txt', 'w') as enc_file:
                enc_file.write(str(encrypted_data))
            messagebox.showinfo("Success", "Text encrypted and saved as 'gnupg_encrypted_text.txt'")

    def decrypt_text(self):
        if self.filepath:
            with open('gnupg_encrypted_text.txt', 'r') as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = self.gpg.decrypt(encrypted_data)
            with open('gnupg_decrypted_text.txt', 'w') as dec_file:
                dec_file.write(str(decrypted_data))
            messagebox.showinfo("Success", "Text decrypted and saved as 'gnupg_decrypted_text.txt'")

if __name__ == "__main__":
    root = tk.Tk()
    app = GnuPGApp(root)
    root.mainloop()
