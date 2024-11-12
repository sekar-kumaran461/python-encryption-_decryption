import customtkinter as ctk
from tkinter import filedialog, messagebox
from PyPDF2 import PdfReader, PdfWriter
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os
from docx import Document

# Constants
BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256

class FileProtectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("File Protector")
        self.geometry("800x600")
        self.configure(bg_color="lightgrey")

        # Title
        self.title_label = ctk.CTkLabel(self, text="File Protector", font=("Helvetica", 24))
        self.title_label.pack(pady=20)

        # Drag-and-drop area
        self.drop_frame = ctk.CTkFrame(self, width=700, height=150, corner_radius=10, fg_color="lightblue")
        self.drop_frame.pack(pady=20)
        self.drop_label = ctk.CTkLabel(self.drop_frame, text="Drag and Drop PDF or DOCX File Here", font=("Helvetica", 16))
        self.drop_label.pack(expand=True)

        # Instructions
        self.instruction_label = ctk.CTkLabel(self, text="Or use the buttons below to select a file", font=("Helvetica", 12))
        self.instruction_label.pack(pady=5)

        # Password Entry
        self.password_label = ctk.CTkLabel(self, text="Enter Password:", font=("Helvetica", 14))
        self.password_label.pack(pady=5)
        self.password_entry = ctk.CTkEntry(self, show="*", width=300)
        self.password_entry.pack(pady=5)

        # File Selection Button
        self.select_file_button = ctk.CTkButton(self, text="Select File", command=self.select_file)
        self.select_file_button.pack(pady=5)

        # Encrypt/Decrypt Buttons
        self.button_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.button_frame.pack(pady=20)

        self.encrypt_button = ctk.CTkButton(self.button_frame, text="Encrypt File", command=self.encrypt_file, width=120)
        self.encrypt_button.grid(row=0, column=0, padx=10)

        self.decrypt_button = ctk.CTkButton(self.button_frame, text="Decrypt & Open File", command=self.decrypt_file, width=120)
        self.decrypt_button.grid(row=0, column=1, padx=10)

        # Download Buttons
        self.download_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.download_frame.pack(pady=20)
        
        self.download_encrypted_button = ctk.CTkButton(self.download_frame, text="Download Encrypted File", command=self.download_encrypted, width=200, state="disabled")
        self.download_encrypted_button.grid(row=0, column=0, padx=10)

        self.download_decrypted_button = ctk.CTkButton(self.download_frame, text="Download Decrypted File", command=self.download_decrypted, width=200, state="disabled")
        self.download_decrypted_button.grid(row=0, column=1, padx=10)

        # Initialize file path variables
        self.file_path = None
        self.encrypted_file_path = None
        self.decrypted_file_path = None

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf"), ("DOCX Files", "*.docx")])
        if self.file_path:
            messagebox.showinfo("File Selected", f"File selected: {os.path.basename(self.file_path)}")

    def encrypt_file(self):
        if self.file_path and self.password_entry.get():
            password = self.password_entry.get()
            try:
                if self.file_path.endswith(".pdf"):
                    self.encrypted_file_path = self.encrypt_pdf(self.file_path, password)
                    messagebox.showinfo("Success", f"PDF encrypted successfully.\nSaved as: {self.encrypted_file_path}")
                elif self.file_path.endswith(".docx"):
                    self.encrypted_file_path = self.encrypt_docx(self.file_path, password)
                    messagebox.showinfo("Success", "DOCX encrypted successfully.")
                
                self.download_encrypted_button.configure(state="normal")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        else:
            messagebox.showwarning("Warning", "Please select a file and enter a password.")

    def decrypt_file(self):
        if self.file_path and self.password_entry.get():
            password = self.password_entry.get()
            try:
                if self.file_path.endswith(".pdf"):
                    content = self.open_protected_pdf(self.file_path, password)
                    self.show_content(content)
                    self.decrypted_file_path = self.file_path.replace(".pdf", "_decrypted.pdf")
                elif self.file_path.endswith(".docx.enc"):
                    self.decrypted_file_path = self.decrypt_docx(self.file_path, password)
                    doc = Document(self.decrypted_file_path)
                    content = "\n".join([p.text for p in doc.paragraphs])
                    self.show_content(content)
                
                self.download_decrypted_button.configure(state="normal")
            except ValueError:
                messagebox.showerror("Error", "Incorrect password or corrupted file.")
        else:
            messagebox.showwarning("Warning", "Please select a file and enter a password.")
    
    def download_encrypted(self):
        if self.encrypted_file_path:
            filedialog.asksaveasfilename(defaultextension=".pdf" if self.encrypted_file_path.endswith(".pdf") else ".enc", 
                                         initialfile=os.path.basename(self.encrypted_file_path))
            messagebox.showinfo("Download", "Encrypted file downloaded successfully.")

    def download_decrypted(self):
        if self.decrypted_file_path:
            filedialog.asksaveasfilename(defaultextension=".pdf" if self.decrypted_file_path.endswith(".pdf") else ".docx", 
                                         initialfile=os.path.basename(self.decrypted_file_path))
            messagebox.showinfo("Download", "Decrypted file downloaded successfully.")

    def show_content(self, content):
        content_window = ctk.CTkToplevel(self)
        content_window.title("File Content")
        content_text = ctk.CTkTextbox(content_window, width=600, height=400)
        content_text.insert("1.0", content)
        content_text.pack(pady=10)
        content_text.configure(state="disabled")

    def encrypt_pdf(self, file_path, password):
        reader = PdfReader(file_path)
        writer = PdfWriter()
        
        for page_num in range(len(reader.pages)):
            writer.add_page(reader.pages[page_num])
        
        writer.encrypt(password)
        encrypted_path = file_path.replace(".pdf", "_encrypted.pdf")
        
        with open(encrypted_path, "wb") as f:
            writer.write(f)
        
        return encrypted_path

    def encrypt_docx(self, file_path, password):
        salt = get_random_bytes(SALT_SIZE)
        key = PBKDF2(password, salt, dkLen=KEY_SIZE)
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        encrypted_path = file_path + ".enc"
        with open(encrypted_path, 'wb') as f:
            f.write(salt + cipher.nonce + tag + ciphertext)
        
        return encrypted_path

    def decrypt_docx(self, file_path, password):
        with open(file_path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        
        key = PBKDF2(password, salt, dkLen=KEY_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Incorrect password or corrupted file")
        
        decrypted_path = file_path.replace(".enc", "_decrypted.docx")
        with open(decrypted_path, 'wb') as f:
            f.write(plaintext)
        
        return decrypted_path

    def open_protected_pdf(self, file_path, password):
        reader = PdfReader(file_path)
        if reader.is_encrypted:
            reader.decrypt(password)
        page_content = reader.pages[0].extract_text()
        return page_content

if __name__ == "__main__":
    ctk.set_appearance_mode("light")
    app = FileProtectorApp()
    app.mainloop()
