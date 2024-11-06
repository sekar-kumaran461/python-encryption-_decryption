import customtkinter as ctk

def get_key(mode="encryption"):
    """
    Displays a CustomTkinter window prompting the user to input an encryption/decryption key.
    
    Parameters:
    - mode (str): "encryption" for the encryption key, "decryption" for the decryption key.
    """
    ctk.set_appearance_mode("System")  # or "Light", "Dark"
    ctk.set_default_color_theme("blue")  # Choose an appropriate color theme

    root = ctk.CTk()
    root.title(f"Enter Key for {mode.capitalize()}")

    # Set window size
    root.geometry("400x200")

    label_text = "Please enter the key (Remember this key for decryption):"
    if mode == "decryption":
        label_text = "Please enter the decryption key:"

    label = ctk.CTkLabel(root, text=label_text)
    label.pack(pady=10)

    key_entry = ctk.CTkEntry(root, show="*", width=300)
    key_entry.pack(pady=10)

    key_value = None

    def submit_key():
        nonlocal key_value
        key_value = key_entry.get().encode('utf-8')
        print(f"Key entered: {key_value}")  # Debugging statement
        root.destroy()

    submit_button = ctk.CTkButton(root, text="Submit", command=submit_key)
    submit_button.pack(pady=10)

    root.mainloop()
    return key_value
get_key()