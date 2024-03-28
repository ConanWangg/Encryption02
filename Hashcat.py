import tkinter as tk
from tkinter import ttk
import hashlib

def encrypt_message():
    message = message_entry.get()
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    hashed_message_label.config(text="Encrypted Message: " + hashed_message)

def save_to_file():
    message = message_entry.get()
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    with open("hashes.txt", "w") as f:
        f.write(hashed_message)
    message_entry.delete(0, tk.END)
    hashed_message_label.config(text="Encrypted Message saved to hashes.txt")

# Create main window
root = tk.Tk()
root.title("Hashcat Encrypter")

# Create widgets
message_label = ttk.Label(root, text="Enter Message:")
message_entry = ttk.Entry(root, width=50)
encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt_message)
hashed_message_label = ttk.Label(root, text="Encrypted Message:")
save_button = ttk.Button(root, text="Save to File", command=save_to_file)

# Layout widgets
message_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
message_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
encrypt_button.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
hashed_message_label.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="w")
save_button.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

root.mainloop()
