import tkinter as tk
from tkinter import messagebox

def on_submit():
    user_input = entry_box.get()
    
    if user_input:
        entry_box.delete(0, tk.END) 
    else:
        messagebox.showwarning("Warning", "The input cannot be empty!")

root = tk.Tk()
root.title("RSA-Cypher app")
root.geometry("1300x850")
root.configure(background='#629FAD')

instruction_label = tk.Label(root, text="Enter the message you want to encrypt:")
instruction_label.pack(pady=100) 

entry_box = tk.Entry(root, width=30)
entry_box.pack(pady=5)

submit_button = tk.Button(root, text="Submit", command=on_submit)
submit_button.pack(pady=20)

root.mainloop()