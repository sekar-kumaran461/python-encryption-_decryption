import customtkinter as ctk
from tkinter import messagebox
import mysql.connector
import re
from PIL import Image
import os
import bcrypt
import smtplib
import random
import subprocess
import sys

class SignupPage:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("Signup Page")
        self.window.geometry("1200x700")
        self.window.configure(fg_color="#1a1a1a")
        
        # Initialize sent_otp as a class variable
        self.sent_otp = None
        
        self.create_db()
        self.create_widgets()
        
    def create_db(self):
        # Establish a connection to MySQL database
        conn = mysql.connector.connect(
            host="localhost",
            user="root",  # Replace with your MySQL username
            password="sk4613123",  # Replace with your MySQL password
            database="encryption_decryption"  # Replace with your database name
        )
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE
            )
        ''')
        conn.commit()
        cursor.close()
        conn.close()

    def create_widgets(self):
        # Main container using grid
        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_columnconfigure(1, weight=1)
        self.window.grid_rowconfigure(0, weight=1)

        # Left Frame (Welcome Section)
        left_frame = ctk.CTkFrame(self.window, fg_color="#2b2b2b", corner_radius=0)
        left_frame.grid(row=0, column=0, sticky="nsew")
        
        # Welcome text
        welcome_label = ctk.CTkLabel(
            left_frame, 
            text="Welcome Back!", 
            font=("Arial Bold", 32),
            text_color="#ffffff"
        )
        welcome_label.place(relx=0.5, rely=0.4, anchor="center")
        
        subtitle_label = ctk.CTkLabel(
            left_frame, 
            text="Sign up to continue your journey", 
            font=("Arial", 16),
            text_color="#bababa"
        )
        subtitle_label.place(relx=0.5, rely=0.47, anchor="center")

        # Right Frame (Login Form)
        right_frame = ctk.CTkFrame(self.window, fg_color="#ffffff", corner_radius=0)
        right_frame.grid(row=0, column=1, sticky="nsew")

        # Form container
        form_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        form_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        title_label = ctk.CTkLabel(
            form_frame, 
            text="Create Account", 
            font=("Arial Bold", 24),
            text_color="#1a1a1a"
        )
        title_label.pack(pady=(0, 20))

        # Username Entry
        self.username_entry = ctk.CTkEntry(
            form_frame,
            width=300,
            height=50,
            placeholder_text="Username",
            font=("Arial", 14),
            corner_radius=25
        )
        self.username_entry.pack(pady=10)

        # Email Entry
        self.email_entry = ctk.CTkEntry(
            form_frame,
            width=300,
            height=50,
            placeholder_text="Email",
            font=("Arial", 14),
            corner_radius=25
        )
        self.email_entry.pack(pady=10)

        # OTP Frame
        otp_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        otp_frame.pack(pady=5)

        self.otp_entry = ctk.CTkEntry(
            otp_frame,
            width=200,
            height=50,
            placeholder_text="Enter OTP",
            font=("Arial", 14),
            corner_radius=25
        )
        self.otp_entry.pack(side="left", padx=5)

        self.otp_button = ctk.CTkButton(
            otp_frame,
            text="Send OTP",
            width=90,
            height=50,
            corner_radius=25,
            command=self.send_otp,
            fg_color="#2b2b2b",
            hover_color="#1a1a1a"
        )
        self.otp_button.pack(side="left", padx=5)

        # Password Entry
        self.password_entry = ctk.CTkEntry(
            form_frame,
            width=300,
            height=50,
            placeholder_text="Password",
            font=("Arial", 14),
            corner_radius=25,
            show="•"
        )
        self.password_entry.pack(pady=10)

        # Confirm Password Entry
        self.confirm_password_entry = ctk.CTkEntry(
            form_frame,
            width=300,
            height=50,
            placeholder_text="Confirm Password",
            font=("Arial", 14),
            corner_radius=25,
            show="•"
        )
        self.confirm_password_entry.pack(pady=10)

        # Signup Button
        self.signup_button = ctk.CTkButton(
            form_frame,
            text="Sign Up",
            width=300,
            height=50,
            corner_radius=25,
            command=self.sign_up,
            font=("Arial Bold", 14),
            fg_color="#2b2b2b",
            hover_color="#1a1a1a"
        )
        self.signup_button.pack(pady=20)

        # Already have an account link
        login_link = ctk.CTkButton(
            form_frame,
            text="Already have an account? Login",
            width=300,
            font=("Arial", 12),
            fg_color="transparent",
            hover_color="#f0f0f0",
            text_color="#1a1a1a",
            command=self.go_to_login
        )
        login_link.pack(pady=10)

    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_password(self, password):
        # At least 8 characters, 1 uppercase, 1 lowercase, 1 number
        if (len(password) >= 8 and
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password)):
            return True
        return False

    def send_otp(self):
        email = self.email_entry.get()
        if not email:
            messagebox.showerror("Error", "Please enter an email!")
            return
        
        if not self.validate_email(email):
            messagebox.showerror("Error", "Please enter a valid email address!")
            return

        try:
            self.sent_otp = random.randint(100000, 999999)
            # Email sending logic (configure with your email settings)
            sender_email = "your-email@gmail.com"
            sender_password = "your-app-specific-password"
            
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)
            message = f"Subject: OTP Verification\n\nYour OTP is {self.sent_otp}"
            server.sendmail(sender_email, email, message)
            server.quit()
            
            messagebox.showinfo("Success", "OTP has been sent to your email!")
            self.otp_button.configure(text="Verify OTP", command=self.verify_otp)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send OTP. Please try again later.")

    def verify_otp(self):
        entered_otp = self.otp_entry.get()
        if not entered_otp:
            messagebox.showerror("Error", "Please enter OTP!")
            return
        
        try:
            if int(entered_otp) == self.sent_otp:
                messagebox.showinfo("Success", "Email verified successfully!")
                self.otp_button.configure(state="disabled", text="Verified")
                return True
            else:
                messagebox.showerror("Error", "Incorrect OTP!")
                return False
        except ValueError:
            messagebox.showerror("Error", "Invalid OTP format!")
            return False

    def sign_up(self):
        username = self.username_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        # Validation
        if not all([username, email, password, confirm_password]):
            messagebox.showerror("Error", "All fields are required!")
            return

        if not self.validate_email(email):
            messagebox.showerror("Error", "Please enter a valid email address!")
            return

        if not self.validate_password(password):
            messagebox.showerror("Error", "Password must be at least 8 characters long and contain uppercase, lowercase, and numbers!")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        if not self.verify_otp():
            messagebox.showerror("Error", "Please verify your email with the correct OTP!")
            return

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            # Connect to the MySQL database
            conn = mysql.connector.connect(
                host="localhost",
                user="your_username",  # Replace with your MySQL username
                password="your_password",  # Replace with your MySQL password
                database="your_database"  # Replace with your database name
            )
            cursor = conn.cursor()

            # Insert the new user into the database
            cursor.execute(
                '''
                INSERT INTO users (username, email, password, is_verified)
                VALUES (%s, %s, %s, %s)
                ''',
                (username, email, hashed_password.decode('utf-8'), True)
            )

            conn.commit()
            cursor.close()
            conn.close()

            messagebox.showinfo("Success", "Account created successfully!")
            self.clear_entries()
            self.go_to_login()

        except mysql.connector.IntegrityError:
            messagebox.showerror("Error", "Username or email already exists!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def clear_entries(self):
        """Clear all the entry fields."""
        self.username_entry.delete(0, 'end')
        self.email_entry.delete(0, 'end')
        self.otp_entry.delete(0, 'end')
        self.password_entry.delete(0, 'end')
        self.confirm_password_entry.delete(0, 'end')

    def go_to_login(self):
        """Redirect to the login page (implement as needed)."""
        # Here you can place logic to open the login page or switch to a different frame
        messagebox.showinfo("Redirect", "Navigate to the login page.")
        # Replace with the logic to open the login page if applicable

# Run the app
if __name__ == "__main__":
    app = SignupPage()
    app.window.mainloop()
