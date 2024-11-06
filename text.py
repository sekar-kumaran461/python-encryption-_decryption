import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
import os
import functions
from menu import EncryptionMenu
class FileEncryptDecryptApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Encryption & Decryption")
        self.geometry("1200x700")
        self.configure(bg="#f0f0f0")
        self.filepath = None
        self.encrypted_data = None
        self.decrypted_data = None
        self.encryption_method = None

        # CustomTkinter appearance
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("green")

        self.create_widgets()

    def create_widgets(self):
        container = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=10)
        container.pack(padx=50, pady=50, fill="both", expand=True)

        left_frame = ctk.CTkFrame(container, fg_color="#1a1a1a", corner_radius=10)
        left_frame.pack(side="left", padx=20, pady=20, fill="both", expand=True)

        self.data_entry_box_label = ctk.CTkLabel(left_frame, text="Enter Data to Encrypt", text_color="white", font=("Arial", 14))
        self.data_entry_box_label.pack(pady=(20, 5))

        self.data_entry_box = ctk.CTkTextbox(left_frame, height=300, width=400, corner_radius=10, text_color="black")
        self.data_entry_box.pack(pady=10)
        self.data_entry_box.insert("1.0", "Enter Data")

        
        self.decrypted_data_box_label = ctk.CTkLabel(left_frame, text="Decrypted Data", text_color="white", font=("Arial", 14))
        self.decrypted_data_box_label.pack(pady=(20, 5))

        self.decrypted_data_box = ctk.CTkTextbox(left_frame, height=300, width=400, corner_radius=10, text_color="black")
        self.decrypted_data_box.pack(pady=10)

        right_frame = ctk.CTkFrame(container, fg_color="#ffffff", corner_radius=10)
        right_frame.pack(side="right", padx=20, pady=20, fill="both", expand=True)

        self.drop_label = ctk.CTkLabel(right_frame, text="Drag and Drop File Here", fg_color="#f0f0f0", width=50, height=10, corner_radius=10, text_color="black")
        self.drop_label.pack(pady=50, fill="both", expand=True)

        upload_button = ctk.CTkButton(right_frame, text="Upload File", command=self.select_file, fg_color="#4CAF50", text_color="white", width=200, corner_radius=10)
        upload_button.pack(pady=20)

        # Encryption Method Selection Button
      
        encrypt_button = ctk.CTkButton(right_frame, text="Encrypt", command=self.encrypt_file, fg_color="#E53935", text_color="white", width=200, corner_radius=10)
        encrypt_button.pack(pady=20)

        self.download_encrypted_button = ctk.CTkButton(right_frame, text="Download Encrypted", command=self.download_encrypted, state="disabled", fg_color="#2196F3", text_color="white", width=200, corner_radius=10)
        self.download_encrypted_button.pack(pady=20)

        decrypt_button = ctk.CTkButton(right_frame, text="Decrypt", command=self.decrypt_file, fg_color="#673AB7", text_color="white", width=200, corner_radius=10)
        decrypt_button.pack(pady=20)

        self.download_decrypted_button = ctk.CTkButton(right_frame, text="Download Decrypted", command=self.download_decrypted, state="disabled", fg_color="#2196F3", text_color="white", width=200, corner_radius=10)
        self.download_decrypted_button.pack(pady=20)

        self.setup_drag_and_drop()

    def setup_drag_and_drop(self):
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        self.filepath = event.data.strip()
        self.drop_label.configure(text=f"File uploaded: {os.path.basename(self.filepath)}", text_color="black")

    def select_file(self):
        self.filepath = filedialog.askopenfilename(title="Select File", filetypes=[("All files", "*.*")])
        if self.filepath:
            self.on_drop(type('Event', (object,), {'data': self.filepath}))

    def select_encryption_method(self):
        # Open encryption method selection window
        menu=EncryptionMenu()
        self.encryption_method = menu.show_menu()

    def encrypt_file(self):
        if self.encryption_method:
            try:
                message = self.data_entry_box.get("1.0", "end-1c").strip()
                if self.filepath.endswith('.txt') or self.filepath.endswith('.pdf'):
                    # Call the encryption function based on selected method
                    if self.encryption_method == "Steganography":
                        self.encrypted_data = functions.encrypt_steganography(self.filepath, message)
                    elif self.encryption_method == "PyCryptodome":
                        self.encrypted_data = functions.encrypt_pycryptodome(self.filepath, message)
                    elif self.encryption_method == "PyNaCl":
                        self.encrypted_data = functions.encrypt_pynacl(self.filepath, message)
                    elif self.encryption_method == "PyAesCrypt":
                        self.encrypted_data = functions.encrypt_pyaescrypt(self.filepath, message)
                    self.encrypted_data_box.delete("1.0", "end")
                    self.encrypted_data_box.insert("1.0", self.encrypted_data)
                    self.download_encrypted_button.configure(state='normal')
                    messagebox.showinfo("Success", f"File encrypted using {self.encryption_method}: {self.encrypted_data}")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        else:
            messagebox.showerror("Error", "No encryption method selected!")

    def decrypt_file(self):
        if self.encryption_method:
            try:
                if self.filepath.endswith('.txt') or self.filepath.endswith('.pdf'):
                    # Call the decryption function based on selected method
                    if self.encryption_method == "Steganography":
                        self.decrypted_data = functions.decrypt_steganography(self.filepath)
                    elif self.encryption_method == "PyCryptodome":
                        self.decrypted_data = functions.decrypt_pycryptodome(self.filepath)
                    elif self.encryption_method == "PyNaCl":
                        self.decrypted_data = functions.decrypt_pynacl(self.filepath)
                    elif self.encryption_method == "PyAesCrypt":
                        self.decrypted_data = functions.decrypt_pyaescrypt(self.filepath)
                    self.encrypted_data_box.delete("1.0", "end")
                    self.encrypted_data_box.insert("1.0", self.encrypted_data)
                    self.decrypted_data_box.delete("1.0", "end")
                    self.decrypted_data_box.insert("1.0", self.decrypted_data)
                    self.download_decrypted_button.configure(state='normal')
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        else:
            messagebox.showerror("Error", "No decryption method selected!")

    def download_encrypted(self):
        if self.encrypted_data:
            messagebox.showinfo("Download", f"Download your encrypted file: {self.encrypted_data}")

    def download_decrypted(self):
        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf")])
        if output_path:
            with open(output_path, "w") as f:
                f.write(self.decrypted_data_box.get("1.0", "end-1c"))
            messagebox.showinfo("Download", f"Decrypted data saved as {output_path}")

if __name__ == "__main__":
    app = FileEncryptDecryptApp()
    app.mainloop()