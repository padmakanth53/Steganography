import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import sys 

# Global variables
encrypt_window = None
decrypt_window = None
generated_password = None
image_label = None
message_entry = None
path_entry = None
decrypt_path_entry = None
decrypt_password_entry = None

# Function to open the file dialog and update the entry box
def browse_image(entry):
    global image_label
    filename = filedialog.askopenfilename(
        title="Select an Image",
        filetypes=(("Image Files", "*.png;*.jpg;*.jpeg;*.gif"),)
    )
    if filename:
        entry.delete(0, tk.END)
        entry.insert(0, filename)

        # Display the selected image
        img = Image.open(filename)
        img = img.resize((200, 200), Image.Resampling.LANCZOS)
        img_tk = ImageTk.PhotoImage(img)

        if image_label is None:
            image_label = tk.Label(encrypt_window, image=img_tk)
            image_label.image = img_tk
            image_label.grid(row=0, column=3, rowspan=5, padx=10, pady=10)
        else:
            image_label.configure(image=img_tk)
            image_label.image = img_tk
            
# Function to open the file dialog and update the entry box for file embedding
def browse_file(entry):
    filename = filedialog.askopenfilename(
        title="Select a .txt File to Embed",
        filetypes=(("Text Files", "*.txt"),)
    )
    if filename:
        entry.delete(0, tk.END)
        entry.insert(0, filename)

def close_application():
    sys.exit() 

# Function to calculate and show capacity and message size
def calculate_storage():
    image_path = path_entry.get() if path_entry else None
    message_path = message_entry.get().strip() if message_type.get() == "file" else None

    if not image_path:
        messagebox.showerror("Error", "Please select an image file.")
        return

    if message_type.get() == "text":
        message = message_entry.get("1.0", tk.END).strip()
        message_length = len(message)
        message_size = message_length / (1024 * 1024)  # Convert characters to MB assuming 1 char = 1 byte
    elif message_type.get() == "file":
        try:
            message_length = os.path.getsize(message_path)
            message_size = message_length / (1024 * 1024)  # Convert bytes to MB
        except Exception as e:
            messagebox.showerror("Error", f"Error reading file: {e}")
            return

    try:
        image = Image.open(image_path)
        max_bits = image.width * image.height * 3  # 3 bits per pixel
        max_bytes = max_bits // 8  # Convert bits to bytes
        max_mb = max_bytes / (1024 * 1024)  # Convert bytes to MB

        messagebox.showinfo("Storage Information", f"The selected image can hold up to {max_mb:.2f} MB.\n"
                                                   f"The current {message_type.get()} uses {message_size:.2f} MB.")
    except Exception as e:
        messagebox.showerror("Error", f"Error calculating storage: {e}")

# Function to generate a random password
def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# AES encryption function with explicit IV handling
def aes_encrypt(data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + "###IV###" + ct

# AES decryption function with explicit IV handling
def aes_decrypt(data, key):
    try:
        iv, ct = data.split("###IV###")
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

# Function to embed encrypted message/file data into the image
def embed_message():
    global generated_password
    image_path = path_entry.get() if path_entry else None
    if not image_path:
        messagebox.showerror("Error", "Please select an image file.")
        return

    try:
        image = Image.open(image_path)
        generated_password = generate_random_password()

        # Text or file selection
        if message_type.get() == "text":
            message = message_entry.get("1.0", tk.END).strip()
            if not message:
                messagebox.showerror("Error", "Please enter a message to embed.")
                return
            encrypted_data = aes_encrypt(("###START###" + message + "###END###").encode('utf-8'), generated_password)

        elif message_type.get() == "file":
            file_path = message_entry.get().strip()
            with open(file_path, 'rb') as f:
                file_data = f.read()
            encrypted_data = aes_encrypt(file_data, generated_password)

        # Combine password and encrypted data
        combined_data = generated_password + "###KEYEND###" + encrypted_data
        binary_message = ''.join(format(ord(char), '08b') for char in combined_data)
        length_binary = format(len(binary_message), '032b')
        binary_message = length_binary + binary_message

        # Embed binary data into image
        index = 0
        for y in range(image.height):
            for x in range(image.width):
                pixel = list(image.getpixel((x, y)))
                for i in range(3):
                    if index < len(binary_message):
                        pixel[i] = pixel[i] & ~1 | int(binary_message[index])
                        index += 1
                image.putpixel((x, y), tuple(pixel))
                if index >= len(binary_message):
                    break
            if index >= len(binary_message):
                break

        open_email_window(image)

    except Exception as e:
        messagebox.showerror("Error", f"Error embedding message: {e}")
        close_application()

# Function to send email with TLS
def send_email(image, sender_email, receiver_email, password, email_window):
    global generated_password
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = 'The Key and Encrypted Image'

        key_message = f'The Key for Encrypted Image is:\n{generated_password}'
        msg.attach(MIMEText(key_message, 'plain'))

        image_path = "temp_image.png"
        image.save(image_path)

        with open(image_path, "rb") as attachment:
            part = MIMEApplication(attachment.read(), Name=os.path.basename(image_path))
            part['Content-Disposition'] = f'attachment; filename={os.path.basename(image_path)}'
            msg.attach(part)

        smtp_server = 'smtp.gmail.com'
        smtp_port = 587

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, password)
            server.send_message(msg)

        messagebox.showinfo("Success", "Email sent successfully.")
        email_window.destroy()
        os.remove(image_path)
        close_application()
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {e}")

def decrypt_message():
    image_path = decrypt_path_entry.get()
    entered_password = decrypt_password_entry.get()

    if not image_path or not entered_password:
        messagebox.showerror("Error", "Please select an image and enter the password.")
        return

    try:
        image = Image.open(image_path)
        binary_message = ""
        length_binary = ""
        index = 0

        # Extract binary data from the image
        for y in range(image.height):
            for x in range(image.width):
                pixel = list(image.getpixel((x, y)))
                for i in range(3):
                    if index < 32:
                        length_binary += str(pixel[i] & 1)
                    else:
                        binary_message += str(pixel[i] & 1)
                    index += 1
                    if index >= 32 and len(binary_message) >= int(length_binary, 2):
                        break
                if index >= 32 and len(binary_message) >= int(length_binary, 2):
                    break
            if index >= 32 and len(binary_message) >= int(length_binary, 2):
                break

        # Convert binary data to string
        data_str = ''.join(chr(int(binary_message[i:i + 8], 2)) for i in range(0, len(binary_message), 8))
        extracted_password, encrypted_data = data_str.split("###KEYEND###")

        # Verify the entered password
        if entered_password != extracted_password:
            messagebox.showerror("Error", "Incorrect password.")
            return

        # Decrypt the data
        decrypted_data = aes_decrypt(encrypted_data, entered_password)

        # Determine if the decrypted data is a message or a file and save it as a .txt file
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            if decrypted_data.startswith("###START###") and decrypted_data.endswith("###END###"):
                # It's a text message
                message = decrypted_data[decrypted_data.index("###START###") + 11 : decrypted_data.index("###END###")]
                with open(file_path, 'w') as file:
                    file.write(message)
                messagebox.showinfo("Success", "Text message decrypted and saved successfully.")
            else:
                # It's a file, but we save it as text format
                with open(file_path, 'w') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Success", "File decrypted and saved successfully.")

    except Exception as e:
        messagebox.showerror("Error", f"Error decrypting message: {e}")
        close_application()


# Function to open the email window for sending encrypted images
def open_email_window(image):
    global encrypt_window

    email_window = tk.Toplevel(encrypt_window)
    email_window.title("Send Email")
    email_window.geometry("400x300")
    email_window.configure(bg="black")

    tk.Label(email_window, text="Sender Email:", bg="black", fg="white").grid(row=0, column=0, padx=10, pady=10)
    tk.Label(email_window, text="Receiver Email:", bg="black", fg="white").grid(row=1, column=0, padx=10, pady=10)
    tk.Label(email_window, text="Sender Password:", bg="black", fg="white").grid(row=2, column=0, padx=10, pady=10)

    sender_email_entry = tk.Entry(email_window)
    sender_email_entry.grid(row=0, column=1, padx=10, pady=10)

    receiver_email_entry = tk.Entry(email_window)
    receiver_email_entry.grid(row=1, column=1, padx=10, pady=10)

    sender_password_entry = tk.Entry(email_window, show="*")
    sender_password_entry.grid(row=2, column=1, padx=10, pady=10)

    send_button = tk.Button(email_window, text="Send Email", command=lambda: send_email(image, sender_email_entry.get(), receiver_email_entry.get(), sender_password_entry.get(), email_window))
    send_button.grid(row=3, column=0, columnspan=2, pady=10)

# Function to close the windows
def close_windows():
    if encrypt_window:
        encrypt_window.destroy()
    if decrypt_window:
        decrypt_window.destroy()

# Function to open the encryption window
def open_encrypt_window():
    global encrypt_window, path_entry, message_entry, message_type, image_label, browse_file_button

    encrypt_window = tk.Toplevel(root)
    encrypt_window.title("Encrypt Message into Image")
    encrypt_window.geometry("600x400")
    encrypt_window.configure(bg="black")

    tk.Label(encrypt_window, text="Select an Image:", bg="black", fg="white").grid(row=0, column=0, padx=10, pady=10)
    path_entry = tk.Entry(encrypt_window, width=50)
    path_entry.grid(row=0, column=1, padx=10, pady=10)
    browse_button = tk.Button(encrypt_window, text="Browse", command=lambda: browse_image(path_entry), bg="blue", fg="white")
    browse_button.grid(row=0, column=2, padx=10, pady=10)

    message_type = tk.StringVar(value="text")
    text_radio = tk.Radiobutton(encrypt_window, text="Text Message", variable=message_type, value="text", bg="black", fg="white", command=lambda: switch_message_entry("text"))
    text_radio.grid(row=1, column=0, padx=10, pady=10)
    file_radio = tk.Radiobutton(encrypt_window, text="File Message", variable=message_type, value="file", bg="black", fg="white", command=lambda: switch_message_entry("file"))
    file_radio.grid(row=1, column=1, padx=10, pady=10)

    message_entry = tk.Text(encrypt_window, width=50, height=10)
    message_entry.grid(row=2, column=0, columnspan=3, padx=10, pady=10)

    calculate_button = tk.Button(encrypt_window, text="Calculate Storage", command=calculate_storage, bg="blue", fg="white")
    calculate_button.grid(row=3, column=0, padx=10, pady=10)

    embed_button = tk.Button(encrypt_window, text="Embed", command=embed_message, bg="blue", fg="white")
    embed_button.grid(row=3, column=1, padx=10, pady=10)

    # Initialize the image label
    image_label = None

    # Disable interaction with the root window while the encrypt window is open
    root.grab_set()

def switch_message_entry(entry_type):
    global message_entry, browse_file_button

    if entry_type == "text":
        if browse_file_button:
            browse_file_button.grid_forget()
        if isinstance(message_entry, tk.Entry):
            message_entry.destroy()
            message_entry = tk.Text(encrypt_window, width=50, height=10)
            message_entry.grid(row=2, column=0, columnspan=3, padx=10, pady=10)
    elif entry_type == "file":
        if isinstance(message_entry, tk.Text):
            message_entry.destroy()
            message_entry = tk.Entry(encrypt_window, width=50)
            message_entry.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
            browse_file_button = tk.Button(encrypt_window, text="Browse", command=lambda: browse_file(message_entry), bg="blue", fg="white")
            browse_file_button.grid(row=2, column=2, padx=10, pady=10)

# Function to open the decryption window
def open_decrypt_window():
    global decrypt_window, decrypt_path_entry, decrypt_password_entry

    decrypt_window = tk.Toplevel(root)
    decrypt_window.title("Decrypt Message from Image")
    decrypt_window.geometry("600x300")
    decrypt_window.configure(bg="black")

    tk.Label(decrypt_window, text="Select an Image:", bg="black", fg="white").grid(row=0, column=0, padx=10, pady=10)
    decrypt_path_entry = tk.Entry(decrypt_window, width=50)
    decrypt_path_entry.grid(row=0, column=1, padx=10, pady=10)
    browse_button = tk.Button(decrypt_window, text="Browse", command=lambda: browse_image(decrypt_path_entry), bg="blue", fg="white")
    browse_button.grid(row=0, column=2, padx=10, pady=10)

    tk.Label(decrypt_window, text="Password:", bg="black", fg="white").grid(row=1, column=0, padx=10, pady=10)
    decrypt_password_entry = tk.Entry(decrypt_window, show="*", width=50)
    decrypt_password_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=10)

    decrypt_button = tk.Button(decrypt_window, text="Decrypt", command=decrypt_message, bg="blue", fg="white")
    decrypt_button.grid(row=2, column=1, padx=10, pady=10)

    # Disable interaction with the root window while the decrypt window is open
    root.grab_set()

# Function to terminate the application
def terminate_application():
    root.destroy()

# Main window setup
root = tk.Tk()
root.title("Steganography Application")
root.geometry("400x200")
root.configure(bg="black")

encrypt_button = tk.Button(root, text="Encrypt Message", command=open_encrypt_window, bg="blue", fg="white")
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt Message", command=open_decrypt_window, bg="blue", fg="white")
decrypt_button.pack(pady=10)

terminate_button = tk.Button(root, text="close", command=terminate_application, bg="blue", fg="white")
terminate_button.pack(pady=10)

root.mainloop()

