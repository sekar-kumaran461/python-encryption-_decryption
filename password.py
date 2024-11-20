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
KEY_SIZE = 32

class FileProtectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("File Protector")
        self.geometry("900x700")
        
        # Set the color theme
        ctk.set_appearance_mode("system")  # Use system theme
        ctk.set_default_color_theme("blue")  # Set default color theme
        
        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)
        
        # Create main container
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)
        
        # Header Section
        self.create_header()
        
        # File Drop Section
        self.create_file_drop_area()
        
        # Password Section
        self.create_password_section()
        
        # Action Buttons Section
        self.create_action_buttons()
        
        # Status Section
        self.create_status_section()
        
        # Initialize file path variables
        self.file_path = None
        self.encrypted_file_path = None
        self.decrypted_file_path = None

    def create_header(self):
        header_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="File Protector",
            font=ctk.CTkFont(family="Helvetica", size=32, weight="bold"),
            text_color=("gray10", "gray90")
        )
        title_label.pack(pady=10)
        
        subtitle_label = ctk.CTkLabel(
            header_frame,
            text="Secure your PDF and DOCX files with encryption",
            font=ctk.CTkFont(size=14),
            text_color=("gray40", "gray60")
        )
        subtitle_label.pack()

    def create_file_drop_area(self):
        self.drop_frame = ctk.CTkFrame(
            self.main_container,
            corner_radius=15,
            fg_color=("gray95", "gray20"),
            border_width=2,
            border_color=("gray70", "gray30")
        )
        self.drop_frame.grid(row=1, column=0, sticky="ew", pady=20, padx=20)
        self.drop_frame.grid_columnconfigure(0, weight=1)
        
        icon_label = ctk.CTkLabel(
            self.drop_frame,
            text="📄",  # File icon
            font=ctk.CTkFont(size=48)
        )
        icon_label.pack(pady=(20, 10))
        
        drop_label = ctk.CTkLabel(
            self.drop_frame,
            text="Drag and Drop File Here",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        drop_label.pack()
        
        supported_files_label = ctk.CTkLabel(
            self.drop_frame,
            text="Supported formats: PDF, DOCX",
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray60")
        )
        supported_files_label.pack(pady=(5, 20))
        
        select_button = ctk.CTkButton(
            self.drop_frame,
            text="Select File",
            command=self.select_file,
            width=200,
            height=40,
            corner_radius=8
        )
        select_button.pack(pady=(0, 20))

    def create_password_section(self):
        password_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        password_frame.grid(row=2, column=0, sticky="ew", pady=20)
        
        password_label = ctk.CTkLabel(
            password_frame,
            text="Password Protection",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        password_label.pack(pady=(0, 10))
        
        self.password_entry = ctk.CTkEntry(
            password_frame,
            show="●",
            width=300,
            height=40,
            placeholder_text="Enter password",
            border_width=2,
            corner_radius=8
        )
        self.password_entry.pack()

    def create_action_buttons(self):
        button_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        button_frame.grid(row=3, column=0, sticky="ew", pady=20)
        button_frame.grid_columnconfigure((0, 1), weight=1)
        
        # Encrypt button
        self.encrypt_button = ctk.CTkButton(
            button_frame,
            text="Encrypt File",
            command=self.encrypt_file,
            width=200,
            height=45,
            corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=("blue", "blue"),
            hover_color=("dark blue", "dark blue")
        )
        self.encrypt_button.grid(row=0, column=0, padx=10, pady=10)
        
        # Decrypt button
        self.decrypt_button = ctk.CTkButton(
            button_frame,
            text="Decrypt & Open File",
            command=self.decrypt_file,
            width=200,
            height=45,
            corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=("green", "green"),
            hover_color=("dark green", "dark green")
        )
        self.decrypt_button.grid(row=0, column=1, padx=10, pady=10)
        
        # Download buttons
        self.download_encrypted_button = ctk.CTkButton(
            button_frame,
            text="Download Encrypted File",
            command=self.download_encrypted,
            width=200,
            height=45,
            corner_radius=8,
            state="disabled",
            font=ctk.CTkFont(size=14),
            fg_color=("gray60", "gray40"),
            hover_color=("gray50", "gray30")
        )
        self.download_encrypted_button.grid(row=1, column=0, padx=10, pady=10)
        
        self.download_decrypted_button = ctk.CTkButton(
            button_frame,
            text="Download Decrypted File",
            command=self.download_decrypted,
            width=200,
            height=45,
            corner_radius=8,
            state="disabled",
            font=ctk.CTkFont(size=14),
            fg_color=("gray60", "gray40"),
            hover_color=("gray50", "gray30")
        )
        self.download_decrypted_button.grid(row=1, column=1, padx=10, pady=10)

    def create_status_section(self):
        self.status_frame = ctk.CTkFrame(
            self.main_container,
            fg_color=("gray95", "gray20"),
            corner_radius=8
        )
        self.status_frame.grid(row=4, column=0, sticky="ew", pady=20, padx=20)
        
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="Ready to protect your files",
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray60")
        )
        self.status_label.pack(pady=10)

    def update_status(self, message, is_error=False):
        self.status_label.configure(
            text=message,
            text_color=("red", "red") if is_error else ("gray40", "gray60")
        )

    def select_file(self):
        self.file_path = filedialog.askopenfilename(
            filetypes=[("PDF Files", "*.pdf"), ("DOCX Files", "*.docx"), ("Encrypted Files", "*.enc")]
        )
        if self.file_path:
            filename = os.path.basename(self.file_path)
            self.update_status(f"Selected file: {filename}")
            messagebox.showinfo("File Selected", f"File selected: {filename}")

    def encrypt_file(self):
        if self.file_path and self.password_entry.get():
            password = self.password_entry.get()
            try:
                if self.file_path.endswith(".pdf"):
                    self.encrypted_file_path = self.encrypt_pdf(self.file_path, password)
                    self.update_status("PDF encrypted successfully!")
                elif self.file_path.endswith(".docx"):
                    self.encrypted_file_path = self.encrypt_docx(self.file_path, password)
                    self.update_status("DOCX encrypted successfully!")
                
                self.download_encrypted_button.configure(state="normal")
            except Exception as e:
                self.update_status(f"Encryption failed: {str(e)}", is_error=True)
                messagebox.showerror("Error", f"Encryption failed: {e}")
        else:
            self.update_status("Please select a file and enter a password", is_error=True)
            messagebox.showwarning("Warning", "Please select a file and enter a password.")

    def decrypt_file(self):
        if self.file_path and self.password_entry.get():
            password = self.password_entry.get()
            try:
                if self.file_path.endswith(".pdf"):
                    content = self.open_protected_pdf(self.file_path, password)
                    self.show_content(content)
                    self.decrypted_file_path = self.file_path.replace(".pdf", "_decrypted.pdf")
                    self.update_status("PDF decrypted successfully!")
                elif self.file_path.endswith(".docx.enc"):
                    self.decrypted_file_path = self.decrypt_docx(self.file_path, password)
                    doc = Document(self.decrypted_file_path)
                    content = "\n".join([p.text for p in doc.paragraphs])
                    self.show_content(content)
                    self.update_status("DOCX decrypted successfully!")
                
                self.download_decrypted_button.configure(state="normal")
            except ValueError:
                self.update_status("Incorrect password or corrupted file", is_error=True)
                messagebox.showerror("Error", "Incorrect password or corrupted file.")
            except Exception as e:
                self.update_status(f"Decryption failed: {str(e)}", is_error=True)
                messagebox.showerror("Error", f"Decryption failed: {e}")
        else:
            self.update_status("Please select a file and enter a password", is_error=True)
            messagebox.showwarning("Warning", "Please select a file and enter a password.")

    def download_encrypted(self):
        if self.encrypted_file_path:
            save_path = filedialog.asksaveasfilename(
                defaultextension=".pdf" if self.encrypted_file_path.endswith(".pdf") else ".enc",
                initialfile=os.path.basename(self.encrypted_file_path)
            )
            if save_path:
                import shutil
                shutil.copy2(self.encrypted_file_path, save_path)
                self.update_status("Encrypted file downloaded successfully!")
                messagebox.showinfo("Success", "Encrypted file downloaded successfully.")

    def download_decrypted(self):
        if self.decrypted_file_path:
            save_path = filedialog.asksaveasfilename(
                defaultextension=".pdf" if self.decrypted_file_path.endswith(".pdf") else ".docx",
                initialfile=os.path.basename(self.decrypted_file_path)
            )
            if save_path:
                import shutil
                shutil.copy2(self.decrypted_file_path, save_path)
                self.update_status("Decrypted file downloaded successfully!")
                messagebox.showinfo("Success", "Decrypted file downloaded successfully.")

    def show_content(self, content):
        content_window = ctk.CTkToplevel(self)
        content_window.title("File Content")
        content_window.geometry("700x500")
        
        title_label = ctk.CTkLabel(
            content_window,
            text="Document Preview",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.pack(pady=20)
        
        content_frame = ctk.CTkFrame(
            content_window,
            fg_color=("white", "gray10"),
            corner_radius=8
        )
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        content_text = ctk.CTkTextbox(
            content_frame,
            width=600,
            height=400,
            font=ctk.CTkFont(size=12),
            corner_radius=0
        )
        content_text.pack(pady=10, padx=10, fill="both", expand=True)
        content_text.insert("1.0", content)
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

    def open_protected_pdf(self, file_path, password):
        reader = PdfReader(file_path)
        if reader.is_encrypted:
            reader.decrypt(password)
        
        content = ""
        for page in reader.pages:
            content += page.extract_text() + "\n\n"
        
        return content

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
            decrypted_path = file_path.replace('.enc', '_decrypted.docx')
            
            with open(decrypted_path, 'wb') as f:
                f.write(plaintext)
            
            return decrypted_path
        except ValueError as e:
            raise ValueError("Incorrect password or corrupted file")
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def handle_drag_drop(self, event):
        file_path = event.data['files'][0] if 'files' in event.data else None
        if file_path and (file_path.endswith('.pdf') or file_path.endswith('.docx') or file_path.endswith('.enc')):
            self.file_path = file_path
            filename = os.path.basename(self.file_path)
            self.update_status(f"Selected file: {filename}")
            messagebox.showinfo("File Selected", f"File selected: {filename}")
        else:
            self.update_status("Invalid file type. Please select a PDF or DOCX file.", is_error=True)
            messagebox.showerror("Error", "Invalid file type. Please select a PDF or DOCX file.")

    def cleanup_temp_files(self):
        """Clean up any temporary files created during encryption/decryption"""
        temp_files = [
            self.encrypted_file_path,
            self.decrypted_file_path
        ]
        
        for file_path in temp_files:
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Error cleaning up temporary file {file_path}: {str(e)}")

    def on_closing(self):
        """Handle application closing"""
        try:
            self.cleanup_temp_files()
        finally:
            self.quit()

def main():
    app = FileProtectorApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()

if __name__ == "__main__":
    main()