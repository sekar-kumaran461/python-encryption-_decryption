import subprocess
import customtkinter as ctk
import sys
from functions import CryptoUtils
import os
from tkinter import filedialog
from PIL import Image, ImageTk
import cv2
import pygame
from tkinter import ttk
import threading
import time

class VideoProcessing(ctk.CTk):
    def __init__(self, method):
        super().__init__()
        
        # Window setup
        self.title("Video & Audio Processing")
        self.geometry("1200x700")
        self.configure(fg_color="#1a1a1a")
        
        # Initialize variables
        self.method = method
        self.crypto_utils = CryptoUtils()
        self.selected_file = None
        self.encryption_key = None
        
        # Video playback variables
        self.video_capture = None
        self.is_playing = False
        self.current_frame = None
        self.play_thread = None
        
        # Initialize pygame mixer for audio
        pygame.mixer.init()
        
        # Configure grid
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Left Frame (File Processing Area)
        left_frame = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=0)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        
        # Title
        title_label = ctk.CTkLabel(
            left_frame,
            text="Video & Audio Processing",
            font=("Arial Bold", 32),
            text_color="#1a1a1a"
        )
        title_label.place(relx=0.5, rely=0.05, anchor="center")
        
        # Video Preview Area
        self.preview_frame = ctk.CTkFrame(
            left_frame,
            width=640,
            height=360,
            fg_color="#f5f5f5",
            corner_radius=10
        )
        self.preview_frame.place(relx=0.5, rely=0.35, anchor="center")
        
        # Preview Label for video display
        self.preview_label = ctk.CTkLabel(
            self.preview_frame,
            text="Drag & Drop Video/Audio Here\nor Click to Select",
            font=("Arial", 14),
            text_color="#666666"
        )
        self.preview_label.place(relx=0.5, rely=0.5, anchor="center")
        
        # Media Controls Frame
        controls_frame = ctk.CTkFrame(
            left_frame,
            fg_color="#f5f5f5",
            corner_radius=10,
            height=50
        )
        controls_frame.place(relx=0.5, rely=0.55, anchor="center", width=640)
        
        # Play/Pause Button
        self.play_button = ctk.CTkButton(
            controls_frame,
            text="▶",
            width=40,
            height=30,
            corner_radius=15,
            command=self.toggle_playback,
            fg_color="#4A3C9C",
            hover_color="#3A2C8C"
        )
        self.play_button.place(relx=0.4, rely=0.5, anchor="center")
        
        # Stop Button
        self.stop_button = ctk.CTkButton(
            controls_frame,
            text="⬛",
            width=40,
            height=30,
            corner_radius=15,
            command=self.stop_playback,
            fg_color="#E74C3C",
            hover_color="#D73C2C"
        )
        self.stop_button.place(relx=0.5, rely=0.5, anchor="center")
        
        # Volume Slider
        self.volume_slider = ctk.CTkSlider(
            controls_frame,
            from_=0,
            to=100,
            number_of_steps=100,
            command=self.update_volume,
            width=100
        )
        self.volume_slider.place(relx=0.7, rely=0.5, anchor="center")
        self.volume_slider.set(50)
        
        # Progress Bar
        self.progress_bar = ttk.Progressbar(
            controls_frame,
            length=580,
            mode='determinate'
        )
        self.progress_bar.place(relx=0.5, rely=0.85, anchor="center")
        
        # File name display
        self.filename_label = ctk.CTkLabel(
            controls_frame,
            text="No file selected",
            font=("Arial", 12),
            text_color="#666666"
        )
        self.filename_label.place(relx=0.5, rely=0.15, anchor="center")
        
        # Make preview frame clickable
        self.preview_frame.bind("<Button-1>", lambda e: self.select_file())
        
        # Text Area for Data Input/Output (moved down)
        input_label = ctk.CTkLabel(
            left_frame,
            text="Encryption/Decryption Status:",
            font=("Arial", 14),
            text_color="#666666"
        )
        input_label.place(relx=0.5, rely=0.65, anchor="center")
        
        self.output_text = ctk.CTkTextbox(
            left_frame,
            width=500,
            height=100,
            fg_color="#f5f5f5",
            corner_radius=10
        )
        self.output_text.place(relx=0.5, rely=0.75, anchor="center")
        
        # Right Frame (Controls Panel) - Keep the same as original
        self._create_right_frame()
        
    def _create_right_frame(self):
        # Right Frame (Controls Panel)
        right_frame = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=0)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        
        # Method display
        method_label = ctk.CTkLabel(
            right_frame,
            text=f"Selected Method: {self.method}",
            font=("Arial Bold", 20),
            text_color="#ffffff"
        )
        method_label.place(relx=0.5, rely=0.1, anchor="center")
        
        # Control buttons
        select_button = ctk.CTkButton(
            right_frame,
            text="Select File",
            width=200,
            height=40,
            corner_radius=20,
            command=self.select_file,
            fg_color="#4A3C9C",
            hover_color="#3A2C8C"
        )
        select_button.place(relx=0.5, rely=0.3, anchor="center")
        
        # Add other buttons (encrypt, decrypt, etc.) as in the original code
        
    def select_file(self):
        """Handle file selection"""
        self.selected_file = filedialog.askopenfilename(
            filetypes=[
                ("Media files", "*.mp4;*.avi;*.mkv;*.mov;*.mp3;*.wav"),
                ("All files", "*.*")
            ]
        )
        if self.selected_file:
            filename = os.path.basename(self.selected_file)
            self.filename_label.configure(text=filename)
            
            # Stop any existing playback
            self.stop_playback()
            
            # Initialize video or audio playback
            if filename.lower().endswith(('.mp4', '.avi', '.mkv', '.mov')):
                self.init_video()
            elif filename.lower().endswith(('.mp3', '.wav')):
                self.init_audio()
    
    def init_video(self):
        """Initialize video playback"""
        if self.video_capture:
            self.video_capture.release()
        
        self.video_capture = cv2.VideoCapture(self.selected_file)
        success, frame = self.video_capture.read()
        if success:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame = cv2.resize(frame, (640, 360))
            photo = ImageTk.PhotoImage(image=Image.fromarray(frame))
            self.preview_label.configure(image=photo)
            self.preview_label.image = photo
    
    def init_audio(self):
        """Initialize audio playback"""
        pygame.mixer.music.load(self.selected_file)
        self.preview_label.configure(text="Audio File Loaded")
    
    def toggle_playback(self):
        """Toggle play/pause for media playback"""
        if not self.selected_file:
            return
            
        if self.is_playing:
            self.pause_playback()
        else:
            self.start_playback()
    
    def start_playback(self):
        """Start media playback"""
        self.is_playing = True
        self.play_button.configure(text="⏸")
        
        if self.selected_file.lower().endswith(('.mp4', '.avi', '.mkv', '.mov')):
            if not self.play_thread or not self.play_thread.is_alive():
                self.play_thread = threading.Thread(target=self.play_video)
                self.play_thread.daemon = True
                self.play_thread.start()
        else:
            pygame.mixer.music.play()
    
    def pause_playback(self):
        """Pause media playback"""
        self.is_playing = False
        self.play_button.configure(text="▶")
        
        if self.selected_file.lower().endswith(('.mp3', '.wav')):
            pygame.mixer.music.pause()
    
    def stop_playback(self):
        """Stop media playback"""
        self.is_playing = False
        self.play_button.configure(text="▶")
        
        if self.video_capture:
            self.video_capture.release()
            self.video_capture = None
        
        pygame.mixer.music.stop()
        self.progress_bar['value'] = 0
    
    def play_video(self):
        """Video playback thread function"""
        while self.is_playing and self.video_capture:
            success, frame = self.video_capture.read()
            if success:
                frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                frame = cv2.resize(frame, (640, 360))
                photo = ImageTk.PhotoImage(image=Image.fromarray(frame))
                self.preview_label.configure(image=photo)
                self.preview_label.image = photo
                
                # Update progress bar
                current_frame = self.video_capture.get(cv2.CAP_PROP_POS_FRAMES)
                total_frames = self.video_capture.get(cv2.CAP_PROP_FRAME_COUNT)
                progress = (current_frame / total_frames) * 100
                self.progress_bar['value'] = progress
                
                time.sleep(1/30)  # Limit framerate
            else:
                self.stop_playback()
                break
    
    def update_volume(self, value):
        """Update volume for audio playback"""
        pygame.mixer.music.set_volume(float(value) / 100)
    
    def go_back(self):
        """Return to main menu"""
        self.stop_playback()  # Stop any playing media
        if self.video_capture:
            self.video_capture.release()
        pygame.mixer.quit()
        self.destroy()
        
        # Start the menu process
        try:
            menu_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "menu.py")
            subprocess.Popen([sys.executable, "menu.py"])
        except Exception as e:
            print(f"Error returning to menu: {e}")
            sys.exit(1)

    def on_closing(self):
        """Clean up resources before closing"""
        self.stop_playback()
        if self.video_capture:
            self.video_capture.release()
        pygame.mixer.quit()
        self.destroy()
        sys.exit()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        method = sys.argv[1]
        app = VideoProcessing(method)
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
    else:
        print("Please specify encryption method")