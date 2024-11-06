import tkinter as tk

class AboutPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        
        label = tk.Label(self, text="About This Tool", font=("Arial", 20))
        label.pack(pady=20)
        
        info_label = tk.Label(self, text="This tool allows you to encode and decode images with steganography.")
        info_label.pack(pady=10)
