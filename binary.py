import subprocess
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
from PIL import Image
import fpdf
from tkinterdnd2 import DND_FILES, TkinterDnD
import re
from functions import CryptoUtils
from menu import EncryptionMenu

import sys

class DragDropFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        self.drop_label = ctk.CTkLabel(
            self,
            text="Drag & Drop File Here\nor Click to Select",
            font=("Helvetica", 16),
            text_color="gray"
        )
        self.drop_label.place(relx=0.5, rely=0.5, anchor="center")
        
        self.bind("<Button-1>", lambda e: self.master.select_file())
        self.drop_label.bind("<Button-1>", lambda e: self.master.select_file())

class EncryptDecryptApp:
    def __init__(self, root, encryption_method=None):
        self.root = root
        self.root.title("File Encryption & Decryption")
        self.root.geometry("1400x800")
        
        # Initialize variables
        self.file_path = None
        self.new_file_path = None
        self.encryption_method = encryption_method or "PyNaCl"
        
        # Initialize encryption handler
        self.crypto_utils = CryptoUtils()
        
        # Configure grid
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        self.create_widgets()
        self.setup_drag_drop()
    
    def create_widgets(self):
        # Left Panel (White Background)
        left_panel = ctk.CTkFrame(self.root, fg_color="#ffffff", corner_radius=0)
        left_panel.grid(row=0, column=0, sticky="nsew")
        
        # Title
        title_label = ctk.CTkLabel(
            left_panel,
            text="File Processing",
            font=("Helvetica", 32, "bold"),
            text_color="#1a1a1a"
        )
        title_label.pack(pady=(40, 20))
        
        # Drag & Drop area
        self.drop_frame = DragDropFrame(
            left_panel,
            width=500,
            height=250,
            fg_color="#f5f5f5",
            corner_radius=15
        )
        self.drop_frame.pack(padx=40, pady=20)
        
        # Input text area
        input_label = ctk.CTkLabel(
            left_panel,
            text="Enter Data to Encrypt:",
            font=("Helvetica", 16),
            text_color="#1a1a1a"
        )
        input_label.pack(pady=(20, 5))
        
        self.input_text = ctk.CTkTextbox(
            left_panel,
            height=150,
            width=500,
            fg_color="#f5f5f5",
            text_color="#1a1a1a",
            corner_radius=10
        )
        self.input_text.pack(padx=40)
        
        # Output text area
        output_label = ctk.CTkLabel(
            left_panel,
            text="Decrypted Data:",
            font=("Helvetica", 16),
            text_color="#1a1a1a"
        )
        output_label.pack(pady=(20, 5))
        
        self.output_text = ctk.CTkTextbox(
            left_panel,
            height=150,
            width=500,
            fg_color="#f5f5f5",
            text_color="#1a1a1a",
            corner_radius=10
        )
        self.output_text.pack(padx=40)
        
        # Right Panel (Black Background)
        right_panel = ctk.CTkFrame(self.root, fg_color="#1a1a1a", corner_radius=0)
        right_panel.grid(row=0, column=1, sticky="nsew")
        
        # Method display
        method_label = ctk.CTkLabel(
            right_panel,
            text=f"Selected Method: {self.encryption_method}",
            font=("Helvetica", 24, "bold"),
            text_color="#ffffff"
        )
        method_label.pack(pady=(40, 20))
        
        # Buttons container
        button_container = ctk.CTkFrame(right_panel, fg_color="transparent")
        button_container.pack(pady=40)
        
        # Main action buttons
        button_styles = {
            "width": 300,
            "height": 50,
            "corner_radius": 25,
            "font": ("Helvetica", 16)
        }
        
        self.select_button = ctk.CTkButton(
            button_container,
            text="Select File",
            command=self.select_file,
            fg_color="#4A3C9C",
            hover_color="#3A2C8C",
            **button_styles
        )
        self.select_button.pack(pady=15)
        
        self.encrypt_button = ctk.CTkButton(
            button_container,
            text="Encrypt",
            command=self.encrypt_file,
            fg_color="#3498DB",
            hover_color="#2488CB",
            **button_styles
        )
        self.encrypt_button.pack(pady=15)
        
        self.decrypt_button = ctk.CTkButton(
            button_container,
            text="Decrypt",
            command=self.decrypt_file,
            fg_color="#9B59B6",
            hover_color="#8B49A6",
            **button_styles
        )
        self.decrypt_button.pack(pady=15)
        
        # Download buttons
        download_container = ctk.CTkFrame(right_panel, fg_color="transparent")
        download_container.pack(pady=20)
        
        self.download_encrypted_button = ctk.CTkButton(
            download_container,
            text="Download Encrypted File",
            command=self.download_encrypted,
            fg_color="#E74C3C",
            hover_color="#D73C2C",
            state="disabled",
            **button_styles
        )
        self.download_encrypted_button.pack(pady=15)
        
        self.download_decrypted_button = ctk.CTkButton(
            download_container,
            text="Download Decrypted as PDF",
            command=self.download_decrypted_pdf,
            fg_color="#2ECC71",
            hover_color="#27AE60",
            state="disabled",
            **button_styles
        )
        self.download_decrypted_button.pack(pady=15)
        
        # Back button
        self.back_button = ctk.CTkButton(
            right_panel,
            text="Back to Menu",
            command=self.go_to_menu,
            fg_color="transparent",
            hover_color="#2b2b2b",
            text_color="#ffffff",
            **button_styles
        )
        self.back_button.pack(pady=(40, 0))
        
        # Status label
        self.status_label = ctk.CTkLabel(
            right_panel,
            text="",
            font=("Helvetica", 14),
            text_color="#bababa"
        )
        self.status_label.pack(pady=20)

    def setup_drag_drop(self):
        self.drop_frame.drop_target_register(DND_FILES)
        self.drop_frame.dnd_bind("<<Drop>>", self.handle_drop)

    def handle_drop(self, event):
        file_path = event.data
        file_path = re.sub(r'[{}]', '', file_path).strip()
        self.load_file(file_path)

    def select_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("All Files", "*.*"), ("Text Files", "*.txt"), ("PDF Files", "*.pdf")]
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                self.file_path = file_path
                self.status_label.configure(text=f"File loaded: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", "Invalid file format or file cannot be opened")
    def select_encryption_method(self):
        # Open encryption method selection window
        menu=EncryptionMenu()
        self.encryption_method = menu.show_menu()

    def encrypt_file(self):
        if self.encryption_method:           
        
            try:
                message = self.input_text.get("1.0", "end-1c")
                
                # Use the appropriate encryption method based on selection
                if self.encryption_method == "PyNaCl":
                    encrypted = self.crypto_utils.nacl_encrypt_file(self.file_path, 
                        f"encrypted_{os.path.basename(self.file_path)}", None)
                elif self.encryption_method == "PyCryptodome":
                    encrypted = self.crypto_utils.rsa_encrypt_file(self.file_path,
                        f"encrypted_{os.path.basename(self.file_path)}", None)
                elif self.encryption_method == "Steganography":
                    self.crypto_utils.hide_file_in_image(self.file_path,
                        message.encode(), f"encrypted_{os.path.basename(self.file_path)}")
                
                self.new_file_path = f"encrypted_{os.path.basename(self.file_path)}"
                self.download_encrypted_button.configure(state="normal")
                self.status_label.configure(text=f"File encrypted successfully using {self.encryption_method}!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        if not self.file_path:
            messagebox.showwarning("Error", "Please select a file first")
            return
        
        try:
            # Use the appropriate decryption method based on selection
            if self.encryption_method == "PyNaCl":
                decrypted = self.crypto_utils.nacl_decrypt_file(self.file_path,
                    f"decrypted_{os.path.basename(self.file_path)}", None)
            elif self.encryption_method == "PyCryptodome":
                decrypted = self.crypto_utils.rsa_decrypt_file(self.file_path,
                    f"decrypted_{os.path.basename(self.file_path)}", None)
            elif self.encryption_method == "Steganography":
                decrypted = self.crypto_utils.extract_file_from_image(self.file_path,
                    f"decrypted_{os.path.basename(self.file_path)}")
            
            # Read and display decrypted content
            with open(f"decrypted_{os.path.basename(self.file_path)}", 'r') as f:
                content = f.read()
                self.output_text.delete("1.0", "end")
                self.output_text.insert("1.0", content)
            
            self.download_decrypted_button.configure(state="normal")
            self.status_label.configure(text=f"File decrypted successfully using {self.encryption_method}!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def download_encrypted(self):
        if not self.new_file_path:
            messagebox.showwarning("Error", "No encrypted file available")
            return
        
        save_path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")],
            initialfile=f"encrypted_{os.path.basename(self.file_path)}"
        )
        
        if save_path:
            try:
                with open(self.new_file_path, 'rb') as src, open(save_path, 'wb') as dst:
                    dst.write(src.read())
                self.status_label.configure(text="Encrypted file saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save encrypted file: {str(e)}")

    def download_decrypted_pdf(self):
        if not self.output_text.get("1.0", "end-1c"):
            messagebox.showwarning("Error", "No decrypted content available")
            return
        
        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            initialfile=f"decrypted_{os.path.basename(self.file_path)}.pdf"
        )
        
        if save_path:
            try:
                pdf = fpdf.FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)
                
                text = self.output_text.get("1.0", "end-1c")
                lines = text.split('\n')
                for line in lines:
                    pdf.multi_cell(0, 10, txt=line)
                
                pdf.output(save_path)
                self.status_label.configure(text="Decrypted content saved as PDF!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save PDF: {str(e)}")

    def go_to_menu(self):
        self.root.destroy()
        subprocess.Popen([sys.executable, "menu.py"])
        sys.exit()

def main():
    # Get encryption method from command line if provided
    encryption_method = sys.argv[1] if len(sys.argv) > 1 else None
    
    root = TkinterDnD.Tk()
    app = EncryptDecryptApp(root, encryption_method)
    root.mainloop()

if __name__ == "__main__":
    main()