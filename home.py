import tkinter as tk
import customtkinter as ctk
from PIL import Image, ImageTk
import subprocess

# Initialize the main window
root = ctk.CTk()
root.geometry("1000x600")
root.title("Encryption & Decryption")

# Set background color for the window
root.configure(fg_color="#F7F8FC")

# Create a container frame
container = ctk.CTkFrame(master=root, width=900, height=500, fg_color="#FFFFFF", corner_radius=15)
container.pack(pady=50, padx=50)

# Add a welcome label
welcome_label = ctk.CTkLabel(
    container,
    text="Welcome to Our Application",
    font=("Arial", 24, "bold")
)
welcome_label.grid(row=0, column=0, columnspan=2, pady=20)

# Add text frame on the left
text_frame = ctk.CTkFrame(master=container, width=400, height=400, fg_color="#F7F8FC", corner_radius=0)
text_frame.grid(row=1, column=0, padx=20, pady=20, sticky="n")

# Title
title_label = ctk.CTkLabel(master=text_frame, text="We offer modern solutions for encryption and decryption",
                           font=("Arial", 18, "bold"), text_color="#2E2E2E", justify="left", wraplength=350)
title_label.pack(pady=10)

# Subtitle
subtitle_label = ctk.CTkLabel(master=text_frame, text="We are a team providing efficient and secure encryption and decryption solutions.",
                              font=("Arial", 14), text_color="#555555", justify="left", wraplength=350)
subtitle_label.pack(pady=10)

# Get Started Button
def on_get_started():
    print("Get Started clicked!")  # Replace this with actual functionality
    root.withdraw()  # Hide the current window
    subprocess.Popen(['python', 'login.py'])  # Make sure 'login.py' exists in the same directory or provide the full path

get_started_button = ctk.CTkButton(master=text_frame, text="Get Started", width=160, height=40, corner_radius=10,
                                   font=("Arial", 14), text_color="white", fg_color="#007BFF", hover_color="#0056b3",
                                   command=on_get_started)
get_started_button.pack(pady=30)

# Load and add an image on the right side using Pillow (example image file path)
image_path = "C:/Users/sekar/OneDrive/Desktop/files/tkinter/stenography/images/a.png"  # Replace with your image path
try:
    image = Image.open(image_path)
    image = image.resize((350, 300))  # Resize to fit layout
    photo = ImageTk.PhotoImage(image)

    # Image frame on the right
    image_frame = ctk.CTkFrame(master=container, width=400, height=400, fg_color="#FFFFFF", corner_radius=0)
    image_frame.grid(row=1, column=1, padx=20, pady=20, sticky="n")

    image_label = ctk.CTkLabel(master=image_frame, image=photo, text="")
    image_label.image = photo  # Keep a reference to avoid garbage collection
    image_label.pack()

except FileNotFoundError:
    print(f"Error: The image at '{image_path}' was not found. Please check the path.")

# Start the Tkinter main loop
root.mainloop()
