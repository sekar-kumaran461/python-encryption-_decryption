import customtkinter as ctk
import sys
import subprocess
from pathlib import Path

class SubMenu(ctk.CTk):
    def __init__(self, method):
        super().__init__()

        # Configure window settings
        self.title(f"{method} Options")
        self.geometry("700x500")
        self.configure(fg_color="#1a1a1a")

        # Store method name
        self.method = method

        # Configure default appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Create the UI
        self.create_widgets()

        # Center the window
        self.center_window()

    def center_window(self):
        self.update()
        width = self.winfo_width()
        height = self.winfo_height()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")

    def create_widgets(self):
        # Main container
        main_frame = ctk.CTkFrame(
            self,
            fg_color="#2b2b2b",
            corner_radius=15
        )
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)

        # Split into two sections: left for descriptions, right for buttons
        left_frame = ctk.CTkFrame(main_frame, fg_color="#333333", width=250)
        left_frame.pack(side="left", fill="both", expand=True, padx=(20, 10), pady=20)

        right_frame = ctk.CTkFrame(main_frame, fg_color="#2b2b2b")
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 20), pady=20)

        # Add descriptions to the left side
        description_label = ctk.CTkLabel(
            left_frame,
            text=f"{self.method} Details",
            font=("Arial Bold", 20),
            text_color="#ffffff"
        )
        description_label.pack(pady=(10, 10))

        description_texts = {
            "Steganography": "Choose to process either text or image for embedding data.",
            "PyCryptodome": "Select binary, text, or image for AES encryption and decryption.",
            "pyAesCrypt": "Encrypt or decrypt binary, text, or image files with simple AES.",
            "PyNaCl": "Supports encryption/decryption of binary, image, text, audio/video, and PDF."
        }
        description_content = description_texts.get(self.method, "No description available.")
        content_label = ctk.CTkLabel(
            left_frame,
            text=description_content,
            font=("Arial", 14),
            text_color="#bababa",
            wraplength=230,
            justify="left"
        )
        content_label.pack(pady=(0, 10))

        # Add buttons to the right side
        button_configs = {
            "Steganography": ["Text", "Image"],
            "PyCryptodome": ["Binary", "Text", "Image"],
            "pyAesCrypt": ["Binary", "Text", "Image"],
            "PyNaCl": ["Binary", "Image", "Text", "Audio/video", "PDF"]
        }

        for button_text in button_configs.get(self.method, []):
            self.create_option_button(right_frame, button_text)

        # Back button at the bottom of the right side
        back_button = ctk.CTkButton(
            right_frame,
            text="Back to Main Menu",
            command=self.quit,
            font=("Arial", 14),
            height=40,
            fg_color="#c53030",
            hover_color="#9b2c2c"
        )
        back_button.pack(pady=20, fill="x", side="bottom")

    def create_option_button(self, parent, text):
        button = ctk.CTkButton(
            parent,
            text=text,
            command=lambda t=text: self.run_process(t.lower()),
            font=("Arial", 15),
            height=45,
            fg_color="#3182ce",
            hover_color="#2c5282",
            corner_radius=8
        )
        button.pack(pady=8, fill="x")

    def run_process(self, input_type):
        file_map = {
            "text": "text.py",
            "image": "image.py",
            "binary": "binary.py",
            "audio/video": "videoaudio.py",
            "pdf": "pdf.py"
        }

        if input_type in file_map:
            script_path = Path(__file__).parent / file_map[input_type]
            if script_path.exists():
                subprocess.run([sys.executable, str(script_path)])
            else:
                print(f"Error: {file_map[input_type]} not found")
        else:
            print("Invalid input type selected.")

        self.quit()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        method = sys.argv[1]
        app = SubMenu(method)
        app.mainloop()
    else:
        print("Please provide a method name as an argument")
