import customtkinter as ctk
import subprocess
import sys
from PIL import Image, ImageTk

class EncryptionMenu(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title("Encryption/Decryption Method")
        self.geometry("1200x700")
        self.configure(fg_color="#1a1a1a")
        
        # Initialize encryption method
        self.encryption_method = None
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Left Frame (Info Panel)
        left_frame = ctk.CTkFrame(self, fg_color="#2b2b2b", corner_radius=0)
        left_frame.grid(row=0, column=0, sticky="nsew")
        
        # Info panel content
        title_label = ctk.CTkLabel(
            left_frame,
            text="Encryption Methods",
            font=("Arial Bold", 32),
            text_color="#ffffff"
        )
        title_label.place(relx=0.5, rely=0.3, anchor="center")
        
        description_label = ctk.CTkLabel(
            left_frame,
            text="Choose your preferred method\nfor secure data protection",
            font=("Arial", 16),
            text_color="#bababa",
            justify="center"
        )
        description_label.place(relx=0.5, rely=0.4, anchor="center")
        
        # Right Frame (Methods Panel)
        right_frame = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=0)
        right_frame.grid(row=0, column=1, sticky="nsew")
        
        # Methods container
        methods_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        methods_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title
        menu_title = ctk.CTkLabel(
            methods_frame,
            text="Select Encryption Method",
            font=("Arial Bold", 24),
            text_color="#1a1a1a"
        )
        menu_title.pack(pady=(0, 30))
        
        # Method descriptions
        methods_info = {
            "Steganography": {
                "color": "#4A3C9C",
                "description": "Hide data within images",
                "hover": "#3A2C8C"
            },
            "PyCryptodome": {
                "color": "#3498DB",
                "description": "Advanced cryptographic algorithms",
                "hover": "#2488CB"
            },
            "PyNaCl": {
                "color": "#9B59B6",
                "description": "High-level cryptographic operations",
                "hover": "#8B49A6"
            },
            "PyAesCrypt": {
                "color": "#E74C3C",
                "description": "File encryption using AES256-CBC",
                "hover": "#D73C2C"
            }
        }
        
        # Create method buttons with descriptions
        for method, info in methods_info.items():
            # Method container
            method_container = ctk.CTkFrame(
                methods_frame,
                fg_color="transparent"
            )
            method_container.pack(pady=15)
            
            # Method button
            button = ctk.CTkButton(
                method_container,
                text=method,
            
                width=300,
                height=50,
                corner_radius=25,
                command=lambda m=method: self.set_encryption_method(m),
                font=("Arial Bold", 14),
                fg_color=info["color"],
                hover_color=info["hover"]
            )
            button.pack()
            
            # Method description
            desc_label = ctk.CTkLabel(
                method_container,
                text=info["description"],
                font=("Arial", 12),
                text_color="#666666"
            )
            desc_label.pack(pady=(5, 0))
            
        # Back button
        back_button = ctk.CTkButton(
            methods_frame,
            text="Back to Home",
            width=300,
            height=40,
            corner_radius=20,
            command=self.go_to_menu,
            font=("Arial", 12),
            fg_color="transparent",
            text_color="#1a1a1a",
            hover_color="#f0f0f0"
        )
        back_button.pack(pady=(30, 0))

    def set_encryption_method(self, method):
        self.encryption_method = method
        self.destroy()
        subprocess.Popen([sys.executable, "submenu.py", method])
        
    def go_to_menu(self):
        self.destroy()
        subprocess.Popen([sys.executable, "menu.py"])
        sys.exit()

    def run(self):
        self.mainloop()

    def show_menu(self):
        self.mainloop()
        return self.encryption_method

if __name__ == "__main__":
    app = EncryptionMenu()
    app.run()