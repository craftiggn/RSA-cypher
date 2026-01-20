import tkinter as tk
from tkinter import messagebox, scrolledtext
import rsa_core
import ecb
import cbc

# --- GLOBAL STATE ---
current_mode = None 
keys = {
    "public": None,
    "private": None,
    "modulus": None,
    "block_size": 8 # Small block size
}
last_encryption = {
    "iv": None,
    "ciphertext": None,
    "mode": None
}


def generate_keys_if_needed():
    if keys["public"] is None:
        try:
            # Generate 64-bit keys 
            e, d, n = rsa_core.keygen(64)
            keys["public"] = e
            keys["private"] = d
            keys["modulus"] = n
            rsa_core.validate_block_size(keys["block_size"], n)
            status_label.config(text="Keys Generated Successfully!")
        except Exception as e:
            messagebox.showerror("Key Gen Error", str(e))

def on_encrypt():
    user_input = entry_box.get("1.0", tk.END).strip() # Get text from Text widget
    
    if not user_input:
        messagebox.showwarning("Warning", "Input cannot be empty")
        return

    generate_keys_if_needed()

    try:
        e, n = keys["public"], keys["modulus"]
        bs = keys["block_size"]

        if current_mode == "ECB":
            encrypted = ecb.encrypt_text(user_input, e, n, bs)
            last_encryption["iv"] = None
            last_encryption["ciphertext"] = encrypted
            last_encryption["mode"] = "ECB"
            
            output_text.set(f"Mode: ECB\nBlock Size: {bs}\nEncrypted Blocks:\n{encrypted}")

        elif current_mode == "CBC":
            iv, encrypted = cbc.encrypt_text(user_input, e, n, bs)
            last_encryption["iv"] = iv
            last_encryption["ciphertext"] = encrypted
            last_encryption["mode"] = "CBC"
            
            output_text.set(f"Mode: CBC\nIV: {iv}\nEncrypted Blocks:\n{encrypted}")

        btn_decrypt.config(state=tk.NORMAL)
        
    except Exception as ex:
        messagebox.showerror("Encryption Error", str(ex))

def on_decrypt():
    if not last_encryption["ciphertext"]:
        messagebox.showwarning("Warning", "Nothing to decrypt yet.")
        return

    try:
        d, n = keys["private"], keys["modulus"]
        bs = keys["block_size"]
        cipher = last_encryption["ciphertext"]
        
        result_msg = ""

        #ECB Mode
        if last_encryption["mode"] == "ECB":
            result_msg = ecb.decrypt_text(cipher, d, n, bs)
        
        #CBC Mode
        elif last_encryption["mode"] == "CBC":
            iv = last_encryption["iv"]
            result_msg = cbc.decrypt_text(cipher, d, n, iv, bs)

        # Show result
        decryption_output.set(f"Decrypted Result:\n{result_msg}")
        
    except Exception as ex:
        messagebox.showerror("Decryption Error", str(ex))

# --- GUI NAVIGATION ---

def show_input_page(mode):
    global current_mode
    current_mode = mode
    mode_label.config(text=f"Current Mode: {current_mode}")
    
    # Reset UI elements
    entry_box.delete("1.0", tk.END)
    output_text.set("Waiting for encryption...")
    decryption_output.set("")
    btn_decrypt.config(state=tk.DISABLED)
    
    selection_frame.pack_forget()
    input_frame.pack(expand=True, fill="both")

def show_selection_page():
    input_frame.pack_forget()
    selection_frame.pack(expand=True, fill="both")

# --- GUI  ---

root = tk.Tk()
root.title("RSA Visualization Tool")
root.geometry("900x700")
root.configure(background='#2C3E50') 


BG_COLOR = '#2C3E50'
FG_COLOR = '#ECF0F1'
BTN_BG = '#E74C3C'
BTN_FG = 'white'
FONT_TITLE = ("Helvetica", 18, "bold")
FONT_NORMAL = ("Helvetica", 11)

#dynamic text updates
output_text = tk.StringVar()
output_text.set("Encrypted data will appear here.")
decryption_output = tk.StringVar()

# === FRAME 1 ===
selection_frame = tk.Frame(root, bg=BG_COLOR)

tk.Label(selection_frame, text="RSA Encryption Visualization", bg=BG_COLOR, fg=FG_COLOR, font=("Helvetica", 24, "bold")).pack(pady=(60, 20))
tk.Label(selection_frame, text="Select an operation mode:", bg=BG_COLOR, fg=FG_COLOR, font=FONT_NORMAL).pack(pady=10)

tk.Button(selection_frame, text="ECB Mode\n(Electronic Codebook)", width=25, height=3, bg='#3498DB', fg='white', font=FONT_NORMAL, 
          command=lambda: show_input_page("ECB")).pack(pady=15)

tk.Button(selection_frame, text="CBC Mode\n(Cipher Block Chaining)", width=25, height=3, bg='#9B59B6', fg='white', font=FONT_NORMAL, 
          command=lambda: show_input_page("CBC")).pack(pady=15)

status_label = tk.Label(selection_frame, text="Keys not generated yet.", bg=BG_COLOR, fg="#BDC3C7", font=("Helvetica", 9, "italic"))
status_label.pack(side=tk.BOTTOM, pady=20)


# === FRAME 2===
input_frame = tk.Frame(root, bg=BG_COLOR)

# Header
header_frame = tk.Frame(input_frame, bg=BG_COLOR)
header_frame.pack(fill="x", pady=20, padx=20)

mode_label = tk.Label(header_frame, text="Mode: Unknown", bg=BG_COLOR, fg="#F1C40F", font=FONT_TITLE)
mode_label.pack(side=tk.LEFT)

tk.Button(header_frame, text="← Back", command=show_selection_page, bg="#95A5A6", fg="black").pack(side=tk.RIGHT)

# Content
content_frame = tk.Frame(input_frame, bg=BG_COLOR)
content_frame.pack(fill="both", expand=True, padx=30)

# Input Section
tk.Label(content_frame, text="1. Enter Plaintext:", bg=BG_COLOR, fg=FG_COLOR, font=("Helvetica", 12, "bold"), anchor="w").pack(fill="x")
entry_box = tk.Text(content_frame, height=3, font=("Consolas", 11))
entry_box.pack(fill="x", pady=5)

# Encrypt Button
tk.Button(content_frame, text="Encrypt ↓", command=on_encrypt, bg="#2ECC71", fg="black", font=("Helvetica", 10, "bold")).pack(pady=10)

# Encryption Output 
tk.Label(content_frame, text="2. Ciphertext (Blocks):", bg=BG_COLOR, fg=FG_COLOR, font=("Helvetica", 12, "bold"), anchor="w").pack(fill="x")
lbl_encrypted = tk.Label(content_frame, textvariable=output_text, bg="#34495E", fg="#2ECC71", font=("Consolas", 10), justify="left", relief="sunken", bd=1, anchor="nw", height=6)
lbl_encrypted.pack(fill="x", pady=5)

# Decrypt Button
btn_decrypt = tk.Button(content_frame, text="Decrypt ↓", command=on_decrypt, bg="#E67E22", fg="black", state=tk.DISABLED, font=("Helvetica", 10, "bold"))
btn_decrypt.pack(pady=10)

# Decryption Output
tk.Label(content_frame, text="3. Restored Plaintext:", bg=BG_COLOR, fg=FG_COLOR, font=("Helvetica", 12, "bold"), anchor="w").pack(fill="x")
lbl_decrypted = tk.Label(content_frame, textvariable=decryption_output, bg="#34495E", fg="#E67E22", font=("Consolas", 11), justify="left", relief="sunken", bd=1, anchor="w", height=3)
lbl_decrypted.pack(fill="x", pady=5)

# Start logic
selection_frame.pack(expand=True, fill="both")
root.mainloop()