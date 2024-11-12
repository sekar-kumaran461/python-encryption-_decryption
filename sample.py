import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
from PIL import Image, ImageTk
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import nacl.secret
import nacl.utils
import pyAesCrypt
import io
import base64

from menu import EncryptionMenu

class ImageSteganographyApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Steganography")
        self.geometry("1200x800")
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.image_path = None
        self.new_image_path = None
        self.encryption_method = "Steganography"  # Default method
        self.preview_image = None
        self.original_format = None
        
        self.create_widgets()

    def create_widgets(self):
        # Main container frame with gradient background
        self.container = ctk.CTkFrame(self, fg_color=("#3F4E6C", "#2C3E50"))
        self.container.pack(padx=20, pady=20, fill="both", expand=True)

        # Create two main columns
        self.create_left_panel()
        self.create_right_panel()

    def create_left_panel(self):
        left_frame = ctk.CTkFrame(self.container, fg_color=("#475D82", "#34495E"))
        left_frame.pack(side="left", padx=15, pady=15, fill="both", expand=True)

        # Title for upload section
        title_label = ctk.CTkLabel(
            left_frame, 
            text="Upload Image",
            font=("Arial Bold", 20),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        title_label.pack(pady=(15, 10))

        # Create drop zone frame
        self.drop_frame = ctk.CTkFrame(
            left_frame,
            fg_color=("#5D6D7E", "#445566"),
            width=300,
            height=300
        )
        self.drop_frame.pack(pady=10, padx=10, fill="both", expand=True)
        self.drop_frame.pack_propagate(False)

        # Image preview label
        self.preview_label = ctk.CTkLabel(
            self.drop_frame,
            text="Drag and Drop Image Here\n(JPG, JPEG, PNG)",
            font=("Arial", 14),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        self.preview_label.pack(expand=True)

        # Image info label
        self.image_info_label = ctk.CTkLabel(
            left_frame,
            text="",
            font=("Arial", 12),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        self.image_info_label.pack(pady=(0, 10))

        # Upload button
        upload_button = ctk.CTkButton(
            left_frame,
            text="Upload Image",
            command=self.upload_image,
            fg_color=("#2ECC71", "#27AE60"),
            hover_color=("#27AE60", "#219A52"),
            height=40
        )
        upload_button.pack(pady=15, padx=20, fill="x")

        # Encryption method selection
        method_label = ctk.CTkLabel(
            left_frame,
            text="Encryption Method:",
            font=("Arial", 14),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        method_label.pack(pady=(15, 5))

        self.encryption_method_var = ctk.StringVar(value="Steganography")
        methods = ["Steganography", "PyCryptodome", "PyNaCl", "PyAesCrypt"]
        self.method_menu = ctk.CTkComboBox(
            left_frame,
            values=methods,
            variable=self.encryption_method_var,
            state="readonly",
            fg_color=("#5D6D7E", "#445566"),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        self.method_menu.pack(pady=5, padx=20, fill="x")

        # Enable drag-and-drop
        self.setup_drag_and_drop()

    def create_right_panel(self):
        right_frame = ctk.CTkFrame(self.container, fg_color=("#475D82", "#34495E"))
        right_frame.pack(side="right", padx=15, pady=15, fill="both", expand=True)

        # Text entry section
        entry_label = ctk.CTkLabel(
            right_frame,
            text="Enter Message",
            font=("Arial Bold", 16),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        entry_label.pack(pady=(15, 5))

        self.data_entry = ctk.CTkTextbox(
            right_frame,
            height=150,
            corner_radius=10,
            fg_color=("#5D6D7E", "#445566"),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        self.data_entry.pack(pady=10, padx=20, fill="x")

        # Action buttons
        button_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        button_frame.pack(pady=15, fill="x")

        encrypt_button = ctk.CTkButton(
            button_frame,
            text="Encrypt Data",
            command=self.encode_data,
            fg_color=("#E74C3C", "#C0392B"),
            hover_color=("#C0392B", "#A93226"),
            height=40
        )
        encrypt_button.pack(pady=5, padx=20, fill="x")

        self.download_button = ctk.CTkButton(
            button_frame,
            text="Download Encrypted Image",
            command=self.download_image,
            state="disabled",
            fg_color=("#3498DB", "#2980B9"),
            hover_color=("#2980B9", "#2573A7"),
            height=40
        )
        self.download_button.pack(pady=5, padx=20, fill="x")

        decode_button = ctk.CTkButton(
            button_frame,
            text="Decode Data",
            command=self.decode_data,
            fg_color=("#9B59B6", "#8E44AD"),
            hover_color=("#8E44AD", "#7D3C98"),
            height=40
        )
        decode_button.pack(pady=5, padx=20, fill="x")

        # Output section
        output_label = ctk.CTkLabel(
            right_frame,
            text="Decoded Message",
            font=("Arial Bold", 16),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        output_label.pack(pady=(15, 5))

        self.decrypted_data_box = ctk.CTkTextbox(
            right_frame,
            height=150,
            corner_radius=10,
            fg_color=("#5D6D7E", "#445566"),
            text_color=("#FFFFFF", "#FFFFFF")
        )
        self.decrypted_data_box.pack(pady=10, padx=20, fill="x")

        self.download_decoded_button = ctk.CTkButton(
            right_frame,
            text="Save Decoded Message",
            command=self.download_decoded_message,
            state="disabled",
            fg_color=("#3498DB", "#2980B9"),
            hover_color=("#2980B9", "#2573A7"),
            height=40
        )
        self.download_decoded_button.pack(pady=5, padx=20, fill="x")

    def encode_data(self):
        if not self.image_path:
            messagebox.showwarning("Image Error", "Please upload an image file first.")
            return

        data = self.data_entry.get("1.0", "end-1c").strip()
        if not data:
            messagebox.showwarning("Input Error", "Please enter text to encode.")
            return

        try:
            # Call method from submenu to select encryption method
            menu = EncryptionMenu  # Assuming EncryptionMenu is the class from submenu.py
            self.encryption_method = menu.show_menu()  # Assuming show_menu() returns the selected encryption method

            # Continue with the rest of the method as usual
            output_dir = os.path.dirname(self.image_path)
            output_path = os.path.join(output_dir, f"encrypted_{os.path.basename(self.image_path)}")
            
            if self.encryption_method == "Steganography":
                img = self.steganography_encode(self.image_path, data)
                img.save(output_path)
                key = None
            elif self.encryption_method == "PyCryptodome":
                key = self.pycryptodome_encrypt(self.image_path, output_path)
            elif self.encryption_method == "PyNaCl":
                key = self.nacl_encrypt(self.image_path, output_path)
            else:  # PyAesCrypt
                key = self.pyaescrypt_encrypt(self.image_path, output_path)

            self.new_image_path = output_path
            self.download_button.configure(state="normal")
            
            if key:
                self.encryption_key = key
                messagebox.showinfo("Success", "Data encrypted successfully! Save the encrypted image and keep the key safe.")
            else:
                messagebox.showinfo("Success", "Data encoded successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")

    def decode_data(self):
        if not self.image_path:
            messagebox.showwarning("Image Error", "Please upload an encrypted image file first.")
            return

        try:
            # Call method from submenu to select encryption method
            menu = EncryptionMenu()  # Assuming EncryptionMenu is the class from submenu.py
            self.encryption_method = menu.show_menu()  # Assuming show_menu() returns the selected encryption method

            if self.encryption_method == "Steganography":
                decoded_data = self.steganography_decode(self.image_path)
            else:
                key = self.get_encryption_key()
                if not key:
                    return
                
                temp_output = os.path.join(os.path.dirname(self.image_path), "temp_decrypted")

                if self.encryption_method == "PyCryptodome":
                    self.pycryptodome_decrypt(self.image_path, temp_output, key)
                elif self.encryption_method == "PyNaCl":
                    self.nacl_decrypt(self.image_path, temp_output, key)
                else:  # PyAesCrypt
                    self.pyaescrypt_decrypt(self.image_path, temp_output, key)

                with open(temp_output, 'rb') as file:
                    decoded_data = file.read().decode()

                os.remove(temp_output)
            
            self.decrypted_data_box.delete("1.0", "end")
            self.decrypted_data_box.insert("1.0", decoded_data)
            self.download_decoded_button.configure(state="normal")
            messagebox.showinfo("Success", "Data decoded successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")

    def get_encryption_key(self):
        """Prompt user for encryption key"""
        key = None
        if hasattr(self, 'encryption_key'):
            key = self.encryption_key
        else:
            # Show dialog to input key
            key = filedialog.askopenfilename(
                title="Select Key File",
                filetypes=[("All Files", "*.*")]
            )
            if not key:
                messagebox.showwarning("Key Required", "Encryption key is required for decryption.")
                return None
        return key

    def setup_drag_and_drop(self):
        """Setup drag and drop functionality"""
        self.drop_frame.drop_target_register(DND_FILES)
        self.drop_frame.dnd_bind('<<Drop>>', self.handle_drop)

    def handle_drop(self, event):
        """Handle drag and drop event"""
        file_path = event.data
        if file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            self.load_image(file_path)
        else:
            messagebox.showwarning("File Error", "Please upload only PNG or JPG images.")

    def load_image(self, file_path):
        """Load and display the image"""
        try:
            self.image_path = file_path
            image = Image.open(file_path)
            self.original_format = image.format
            
            # Resize image for preview while maintaining aspect ratio
            display_size = (280, 280)
            image.thumbnail(display_size, Image.Resampling.LANCZOS)
            
            # Convert to PhotoImage
            photo = ImageTk.PhotoImage(image)
            
            # Update preview
            self.preview_label.configure(image=photo, text="")
            self.preview_label.image = photo
            
            # Update image info
            file_size = os.path.getsize(file_path) / 1024  # Convert to KB
            self.image_info_label.configure(
                text=f"Size: {file_size:.1f}KB\nFormat: {self.original_format}\n"
                     f"Dimensions: {image.size[0]}x{image.size[1]}"
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")

    def upload_image(self):
        """Open file dialog to upload image"""
        file_path = filedialog.askopenfilename(
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.load_image(file_path)

    def download_image(self):
        """Save the encrypted image"""
        if not self.new_image_path:
            messagebox.showwarning("Error", "No encrypted image to save.")
            return
            
        save_path = filedialog.asksaveasfilename(
            defaultextension=f".{self.original_format.lower()}",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )
        
        if save_path:
            try:
                # If we have an encryption key, save it separately
                if hasattr(self, 'encryption_key'):
                    key_path = save_path + ".key"
                    with open(key_path, 'wb') as key_file:
                        key_file.write(self.encryption_key)
                    messagebox.showinfo("Success", 
                        "Encrypted image and key file saved successfully!\n"
                        f"Key saved to: {key_path}"
                    )
                
                # Copy the encrypted image to the selected location
                with open(self.new_image_path, 'rb') as src, open(save_path, 'wb') as dst:
                    dst.write(src.read())
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save image: {str(e)}")

    def download_decoded_message(self):
        """Save the decoded message to a text file"""
        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if save_path:
            try:
                decoded_text = self.decrypted_data_box.get("1.0", "end-1c")
                with open(save_path, 'w', encoding='utf-8') as file:
                    file.write(decoded_text)
                messagebox.showinfo("Success", "Decoded message saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save decoded message: {str(e)}")

if __name__ == "__main__":
    app = ImageSteganographyApp()
    app.mainloop()