import customtkinter as ctk
from tkinter import filedialog, messagebox
from nacl.secret import SecretBox
from nacl.utils import random

class PDFEncryptDecryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF File Encryption & Decryption with PyNaCl")
        self.root.geometry("600x400")
        self.key = random(SecretBox.KEY_SIZE)
        self.box = SecretBox(self.key)
        self.pdf_path = None

        # Layout for PDF file input/output
        self.select_button = ctk.CTkButton(self.root, text="Select PDF File", command=self.select_pdf)
        self.select_button.pack(pady=10)

        self.encrypt_button = ctk.CTkButton(self.root, text="Encrypt PDF", command=self.encrypt_pdf)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = ctk.CTkButton(self.root, text="Decrypt PDF", command=self.decrypt_pdf)
        self.decrypt_button.pack(pady=10)

    def select_pdf(self):
        self.pdf_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if self.pdf_path:
            messagebox.showinfo("Selected", f"Selected File: {self.pdf_path}")

    def encrypt_pdf(self):
        if self.pdf_path:
            with open(self.pdf_path, 'rb') as f:
                pdf_data = f.read()
            encrypted = self.box.encrypt(pdf_data)
            with open('pdf_encrypted.aes', 'wb') as f:
                f.write(encrypted)
            messagebox.showinfo("Success", "PDF Encrypted and saved!")

    def decrypt_pdf(self):
        if self.pdf_path:
            with open('pdf_encrypted.aes', 'rb') as f:
                encrypted = f.read()
            decrypted = self.box.decrypt(encrypted)
            with open('decrypted_pdf.pdf', 'wb') as f:
                f.write(decrypted)
            messagebox.showinfo("Success", "PDF Decrypted and saved!")

if __name__ == "__main__":
    root = ctk.CTk()
    app = PDFEncryptDecryptApp(root)
    root.mainloop()
