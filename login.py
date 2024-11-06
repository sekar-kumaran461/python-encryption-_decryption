import customtkinter as ctk
from tkinter import messagebox
import subprocess
import time
from threading import Thread
import mysql.connector

# Configure appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Function to connect to the MySQL database
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="sk4613123",  # Replace with your MySQL password
            database="encryption_decryption"   # Replace with your database name
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

def show_message(frame, message, is_error=False):
    color = "#ff4444" if is_error else "#00ff00"
    message_label = ctk.CTkLabel(
        frame,
        text=message,
        text_color=color,
        font=ctk.CTkFont(size=12)
    )
    message_label.place(relx=0.5, rely=0.15, anchor="center")
    root.after(3000, message_label.destroy)

def perform_login():
    username = username_entry.get()
    password = password_entry.get()
    
    if not username or not password:
        show_message(login_frame, "Please enter both username and password", is_error=True)
        return
    
    loading_frame.place(relx=0.5, rely=0.5, anchor="center")
    progress.set(0)
    
    def login_animation():
        for i in range(100):
            progress.set(i / 100)
            time.sleep(0.01)
        root.after(0, complete_login)
    
    Thread(target=login_animation).start()

def complete_login():
    username = username_entry.get()
    password = password_entry.get()
    
    loading_frame.place_forget()
    
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        connection.close()
        
        if result:
            show_message(login_frame, "Login successful!")
            root.after(1000, lambda: open_main_menu(username))
        else:
            show_message(login_frame, "Invalid credentials", is_error=True)
    else:
        show_message(login_frame, "Database connection error", is_error=True)

def open_main_menu(username):
    root.withdraw()
    subprocess.Popen(['python', 'menu.py', username])
    root.destroy()

def open_signup():
    root.withdraw()
    subprocess.Popen(['python', 'signup.py'])
    root.destroy()

def open_forgot_password():
    root.withdraw()
    subprocess.Popen(['python', 'forgot_password.py'])
    root.destroy()

# Create main window
root = ctk.CTk()
root.title("Login")
root.geometry("1100x700")
root.resizable(True, True)

# Configure grid layout
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# Create sidebar frame
sidebar_frame = ctk.CTkFrame(
    root,
    width=400,
    corner_radius=0,
    fg_color="#1a1a1a"
)
sidebar_frame.grid(row=0, column=0, sticky="nsew")
sidebar_frame.grid_rowconfigure(4, weight=1)

# Logo and welcome text
logo_label = ctk.CTkLabel(
    sidebar_frame,
    text="COMPANY",
    font=ctk.CTkFont(size=40, weight="bold"),
    text_color="#4A9EFF"
)
logo_label.grid(row=0, column=0, padx=60, pady=(100, 30))

welcome_label = ctk.CTkLabel(
    sidebar_frame,
    text="Welcome Back!",
    font=ctk.CTkFont(size=24, weight="bold"),
    text_color="#ffffff"
)
welcome_label.grid(row=1, column=0, padx=60, pady=(0, 15))

subtitle_label = ctk.CTkLabel(
    sidebar_frame,
    text="Please login to your account",
    font=ctk.CTkFont(size=14),
    text_color="#666666"
)
subtitle_label.grid(row=2, column=0, padx=60, pady=(0, 30))

# Create main frame
main_frame = ctk.CTkFrame(
    root,
    fg_color="#212121",
    corner_radius=0
)
main_frame.grid(row=0, column=1, sticky="nsew")

# Create login frame
login_frame = ctk.CTkFrame(
    main_frame,
    width=400,
    height=450,
    fg_color="#2b2b2b",
    corner_radius=15
)
login_frame.place(relx=0.5, rely=0.5, anchor="center")
login_frame.grid_propagate(False)

# Login header
login_label = ctk.CTkLabel(
    login_frame,
    text="Login",
    font=ctk.CTkFont(size=24, weight="bold"),
    text_color="#ffffff"
)
login_label.place(relx=0.5, rely=0.1, anchor="center")

# Username frame
username_frame = ctk.CTkFrame(
    login_frame,
    fg_color="transparent",
    width=300,
    height=70
)
username_frame.place(relx=0.5, rely=0.3, anchor="center")
username_frame.grid_propagate(False)

username_label = ctk.CTkLabel(
    username_frame,
    text="Username",
    font=ctk.CTkFont(size=14),
    text_color="#666666"
)
username_label.pack(anchor="w", pady=(0, 5))

username_entry = ctk.CTkEntry(
    username_frame,
    placeholder_text="Enter your username",
    font=ctk.CTkFont(size=14),
    height=45,
    fg_color="#333333",
    border_color="#4A9EFF",
    border_width=1,
    width=300
)
username_entry.pack(fill="x")

# Password frame
password_frame = ctk.CTkFrame(
    login_frame,
    fg_color="transparent",
    width=300,
    height=70
)
password_frame.place(relx=0.5, rely=0.5, anchor="center")
password_frame.grid_propagate(False)

password_label = ctk.CTkLabel(
    password_frame,
    text="Password",
    font=ctk.CTkFont(size=14),
    text_color="#666666"
)
password_label.pack(anchor="w", pady=(0, 5))

password_entry = ctk.CTkEntry(
    password_frame,
    placeholder_text="Enter your password",
    font=ctk.CTkFont(size=14),
    height=45,
    fg_color="#333333",
    border_color="#4A9EFF",
    border_width=1,
    width=300,
    show="●"
)
password_entry.pack(fill="x")

# Remember me and forgot password frame
options_frame = ctk.CTkFrame(
    login_frame,
    fg_color="transparent",
    width=300,
    height=30
)
options_frame.place(relx=0.5, rely=0.65, anchor="center")
options_frame.grid_propagate(False)

remember_var = ctk.BooleanVar()
remember_checkbox = ctk.CTkCheckBox(
    options_frame,
    text="Remember me",
    font=ctk.CTkFont(size=12),
    text_color="#666666",
    fg_color="#4A9EFF",
    variable=remember_var
)
remember_checkbox.pack(side="left")

forgot_button = ctk.CTkButton(
    options_frame,
    text="Forgot Password?",
    font=ctk.CTkFont(size=12),
    text_color="#4A9EFF",
    fg_color="transparent",
    hover=False,
    command=open_forgot_password
)
forgot_button.pack(side="right")

# Login button
login_button = ctk.CTkButton(
    login_frame,
    text="Login",
    font=ctk.CTkFont(size=15, weight="bold"),
    text_color="#ffffff",
    fg_color="#4A9EFF",
    hover_color="#1f6feb",
    height=45,
    width=300,
    command=perform_login
)
login_button.place(relx=0.5, rely=0.8, anchor="center")

# Sign up frame
signup_frame = ctk.CTkFrame(
    login_frame,
    fg_color="transparent",
    width=300,
    height=30
)
signup_frame.place(relx=0.5, rely=0.9, anchor="center")
signup_frame.grid_propagate(False)

signup_label = ctk.CTkLabel(
    signup_frame,
    text="Don't have an account?",
    font=ctk.CTkFont(size=12),
    text_color="#666666"
)
signup_label.pack(side="left", padx=(50, 5))

signup_button = ctk.CTkButton(
    signup_frame,
    text="Sign Up",
    font=ctk.CTkFont(size=12),
    text_color="#4A9EFF",
    fg_color="transparent",
    hover=False,
    command=open_signup
)
signup_button.pack(side="left")

# Create loading frame
loading_frame = ctk.CTkFrame(
    root,
    fg_color="#212121",
    width=200,
    height
    =100,
    corner_radius=15
)
loading_frame.grid_propagate(False)

# Progress bar for loading animation
progress = ctk.DoubleVar()
loading_progressbar = ctk.CTkProgressBar(
    loading_frame,
    variable=progress,
    mode="determinate",
    width=150,
    fg_color="#333333",
    progress_color="#4A9EFF"
)
loading_progressbar.pack(pady=20)

loading_label = ctk.CTkLabel(
    loading_frame,
    text="Logging in...",
    font=ctk.CTkFont(size=14),
    text_color="#4A9EFF"
)
loading_label.pack()

# Start the main event loop
root.mainloop()
