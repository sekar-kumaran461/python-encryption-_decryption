import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
from PIL import Image, ImageTk
import os
from menu import EncryptionMenu
import functions

class ImageSteganographyApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Steganography")
        self.geometry("1200x800")
        
        # Set appearance mode and theme for CustomTkinter
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize variables
        self.image_path = None
        self.new_image_path = None
        self.encryption_method = None
        self.preview_image = None
        self.original_format = None
        self.crypto_utils = functions.CryptoUtils()  # Initialize CryptoUtils
        
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

    def setup_drag_and_drop(self):
        self.drop_frame.drop_target_register(DND_FILES)
        self.drop_frame.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        self.image_path = event.data.strip()
        if self.image_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            self.update_preview_image()
        else:
            messagebox.showerror("Error", "Please upload a valid image file (JPG, JPEG, or PNG).")

    def upload_image(self):
        self.image_path = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[
                ("All supported formats", "*.jpg;*.jpeg;*.png"),
                ("JPEG files", "*.jpg;*.jpeg"),
                ("PNG files", "*.png")
            ]
        )
        if self.image_path:
            self.update_preview_image()

    def update_preview_image(self):
        try:
            # Open and get image information
            with Image.open(self.image_path) as img:
                self.original_format = img.format
                width, height = img.size
                file_size = os.path.getsize(self.image_path) / 1024  # Convert to KB

                # Calculate aspect ratio for preview
                aspect_ratio = width / height
                preview_width = 280
                preview_height = int(preview_width / aspect_ratio)
                
                # Ensure preview height doesn't exceed frame
                if preview_height > 280:
                    preview_height = 280
                    preview_width = int(preview_height * aspect_ratio)

                # Create preview image
                preview_img = img.copy()
                preview_img.thumbnail((preview_width, preview_height), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(preview_img)
                
                # Update preview label
                self.preview_label.configure(image=photo, text="")
                self.preview_label.image = photo  # Keep a reference

                # Update image info label
                info_text = f"Format: {self.original_format} | Size: {width}x{height} | File size: {file_size:.1f}KB"
                self.image_info_label.configure(text=info_text)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")

    def encode_data(self):
        if not self.image_path:
            messagebox.showwarning("Image Error", "Please upload an image file first.")
            return
            
        data = self.data_entry.get("1.0", "end-1c").strip()
        if not data:
            messagebox.showwarning("Input Error", "Please enter text to encode.")
            return

        try:
            # Get encryption method from menu selection
            menu = EncryptionMenu()
            self.encryption_method = menu.show_menu()
            
            if self.encryption_method:
                # Create temporary output path
                output_path = os.path.join(os.path.dirname(self.image_path), 
                                         f"temp_encrypted_{os.path.basename(self.image_path)}")
                
                # Apply encryption based on selected method
                if self.encryption_method == "Steganography":
                    self.crypto_utils.hide_file_in_image(self.image_path, data.encode(), output_path)
                elif self.encryption_method == "PyCryptodome":
                    key = self.crypto_utils.aes_encrypt_file(self.image_path, output_path)
                    messagebox.showinfo("Key", f"Your encryption key is: {key.hex()}\nPlease save this for decryption.")
                elif self.encryption_method == "PyNaCl":
                    key = self.crypto_utils.nacl_encrypt_file(self.image_path, output_path)
                    messagebox.showinfo("Key", f"Your encryption key is: {key.hex()}\nPlease save this for decryption.")
                elif self.encryption_method == "PyAesCrypt":
                    key = self.crypto_utils.aes_encrypt_file(self.image_path, output_path)  # Using AES for PyAesCrypt
                    messagebox.showinfo("Key", f"Your encryption key is: {key.hex()}\nPlease save this for decryption.")
                
                self.new_image_path = output_path
                self.download_button.configure(state="normal")
                messagebox.showinfo("Success", "Data encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode_data(self):
        if not self.image_path:
            messagebox.showwarning("Image Error", "Please upload an image file first.")
            return

        try:
            # Get encryption method from menu selection
            menu = EncryptionMenu()
            self.encryption_method = menu.show_menu()
            
            if self.encryption_method:
                if self.encryption_method == "Steganography":
                    decoded_data = self.crypto_utils.extract_file_from_image(self.image_path, "temp_decoded")
                elif self.encryption_method in ["PyCryptodome", "PyAesCrypt"]:
                    key = messagebox.askstring("Key Required", "Please enter your decryption key (hex format):")
                    if key:
                        output_path = "temp_decrypted_image"
                        self.crypto_utils.aes_decrypt_file(self.image_path, output_path, bytes.fromhex(key))
                        with open(output_path, 'r') as f:
                            decoded_data = f.read()
                        os.remove(output_path)
                elif self.encryption_method == "PyNaCl":
                    key = messagebox.askstring("Key Required", "Please enter your decryption key (hex format):")
                    if key:
                        output_path = "temp_decrypted_image"
                        self.crypto_utils.nacl_decrypt_file(self.image_path, output_path, bytes.fromhex(key))
                        with open(output_path, 'r') as f:
                            decoded_data = f.read()
                        os.remove(output_path)
                
                self.decrypted_data_box.delete("1.0", "end")
                self.decrypted_data_box.insert("1.0", decoded_data)
                self.download_decoded_button.configure(state="normal")
                messagebox.showinfo("Success", "Data decoded successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def download_image(self):
        if self.new_image_path:
            # Determine the default extension based on original format
            default_ext = ".png"  # Default to PNG for best quality
            filetypes = [
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("All files", "*.*")
            ]
            
            save_path = filedialog.asksaveasfilename(
                defaultextension=default_ext,
                filetypes=filetypes,
                initialfile=f"encrypted_image{default_ext}"
            )
            
            if save_path:
                try:
                    # If saving as JPEG/JPG, convert to RGB first
                    if save_path.lower().endswith(('.jpg', '.jpeg')):
                        with Image.open(self.new_image_path) as img:
                            if img.mode in ('RGBA', 'P'):
                                img = img.convert('RGB')
                            img.save(save_path, 'JPEG', quality=95)
                        os.remove(self.new_image_path)  # Remove temporary PNG
                    else:
                        os.rename(self.new_image_path, save_path)
                    
                    messagebox.showinfo("Success", "Image saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save image: {str(e)}")

    def download_decoded_message(self):
        decoded_message = self.decrypted_data_box.get("1.0", "end-1c").strip()
        if decoded_message:
            save_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                initialfile="decoded_message.txt"
            )
            if save_path:
                try:
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(decoded_message)
                    messagebox.showinfo("Success", "Message saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save message: {str(e)}")
        else:
            messagebox.showwarning("Error", "No decoded message available.")

if __name__ == "__main__":
    app = ImageSteganographyApp()
    app.mainloop()