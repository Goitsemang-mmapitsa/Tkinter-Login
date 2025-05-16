import tkinter as tk
from tkinter import font, messagebox
import sqlite3
import re
import hashlib
import os

# Initialize the main application window
app = tk.Tk()
app.title("Figma Styled Registration Form")

# Get the screen width and height
screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()

# Set the window size to the screen size
app.geometry(f"{screen_width}x{screen_height}")

# Define Figma colors and fonts
figma_bg_color = "#F3F4F6"
figma_primary_color = "#1ABCFE"
figma_secondary_color = "#0ACF83"
figma_font = ("Helvetica Neue", 12)

# Create a top frame with a primary background
top_frame = tk.Frame(app, bg=figma_primary_color, height=50)
top_frame.pack(fill="x")

label = tk.Label(top_frame, text="Figma Styled App", font=("Helvetica Neue", 14, "bold"), fg="white", bg=figma_primary_color)
label.pack(side="left", padx=10)

# Add registration, login, and admin buttons to the top frame
register_button = tk.Button(top_frame, text="Register", font=figma_font, bg=figma_secondary_color, fg="white", command=lambda: show_form(form_frame))
register_button.pack(side="right", padx=10)

login_button = tk.Button(top_frame, text="Login", font=figma_font, bg=figma_secondary_color, fg="white", command=lambda: show_form(login_frame))
login_button.pack(side="right", padx=10)

admin_button = tk.Button(top_frame, text="Admin", font=figma_font, bg=figma_secondary_color, fg="white", command=lambda: show_form(admin_frame))
admin_button.pack(side="left", padx=10)

# Create the registration form
form_frame = tk.Frame(app, padx=20, pady=20, bg=figma_bg_color)

tk.Label(form_frame, text="First Name:", font=figma_font, bg=figma_bg_color).grid(row=0, column=0, sticky="e")
tk.Label(form_frame, text="Last Name:", font=figma_font, bg=figma_bg_color).grid(row=1, column=0, sticky="e")
tk.Label(form_frame, text="Email:", font=figma_font, bg=figma_bg_color).grid(row=2, column=0, sticky="e")
tk.Label(form_frame, text="Password:", font=figma_font, bg=figma_bg_color).grid(row=3, column=0, sticky="e")

first_name_entry = tk.Entry(form_frame, font=figma_font)
last_name_entry = tk.Entry(form_frame, font=figma_font)
email_entry = tk.Entry(form_frame, font=figma_font)
password_entry = tk.Entry(form_frame, font=figma_font, show="*")

first_name_entry.grid(row=0, column=1, pady=5)
last_name_entry.grid(row=1, column=1, pady=5)
email_entry.grid(row=2, column=1, pady=5)
password_entry.grid(row=3, column=1, pady=5)

# Add acceptance buttons for registration
accept_button = tk.Button(form_frame, text="Accept", font=figma_font, bg=figma_primary_color, fg="white", command=validate_registration)
accept_button.grid(row=4, column=0, pady=10)

cancel_button = tk.Button(form_frame, text="Cancel", font=figma_font, bg=figma_primary_color, fg="white", command=lambda: form_frame.pack_forget())
cancel_button.grid(row=4, column=1, pady=10)

# Create the login form
login_frame = tk.Frame(app, padx=20, pady=20, bg=figma_bg_color)

tk.Label(login_frame, text="Email:", font=figma_font, bg=figma_bg_color).grid(row=0, column=0, sticky="e")
tk.Label(login_frame, text="Password:", font=figma_font, bg=figma_bg_color).grid(row=1, column=0, sticky="e")

login_email_entry = tk.Entry(login_frame, font=figma_font)
login_password_entry = tk.Entry(login_frame, font=figma_font, show="*")

login_email_entry.grid(row=0, column=1, pady=5)
login_password_entry.grid(row=1, column=1, pady=5)

# Add acceptance buttons for login
login_accept_button = tk.Button(login_frame, text="Accept", font=figma_font, bg=figma_primary_color, fg="white", command=validate_login)
login_accept_button.grid(row=2, column=0, pady=10)

login_cancel_button = tk.Button(login_frame, text="Cancel", font=figma_font, bg=figma_primary_color, fg="white", command=lambda: login_frame.pack_forget())
login_cancel_button.grid(row=2, column=1, pady=10)

# Create the admin form
admin_frame = tk.Frame(app, padx=20, pady=20, bg=figma_bg_color)

tk.Label(admin_frame, text="Admin Email:", font=figma_font, bg=figma_bg_color).grid(row=0, column=0, sticky="e")
tk.Label(admin_frame, text="Admin Password:", font=figma_font, bg=figma_bg_color).grid(row=1, column=0, sticky="e")

admin_email_entry = tk.Entry(admin_frame, font=figma_font)
admin_password_entry = tk.Entry(admin_frame, font=figma_font, show="*")

admin_email_entry.grid(row=0, column=1, pady=5)
admin_password_entry.grid(row=1, column=1, pady=5)

# Add OK and Cancel buttons to the admin form
admin_ok_button = tk.Button(admin_frame, text="OK", font=figma_font, bg=figma_primary_color, fg="white", command=validate_admin)
admin_ok_button.grid(row=2, column=0, pady=10)

admin_cancel_button = tk.Button(admin_frame, text="Cancel", font=figma_font, bg=figma_primary_color, fg="white", command=lambda: admin_frame.pack_forget())
admin_cancel_button.grid(row=2, column=1, pady=10)

# Create the center frame
center_frame = tk.Frame(app, padx=20, pady=20, bg=figma_bg_color)

def hash_password(password):
    # Generate a random salt
    salt = os.urandom(16)
    # Hash the password with PBKDF2
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    # Return the salt and hashed password concatenated
    return salt + hashed_password

def check_password(stored_password, provided_password):
    # Extract the salt and stored hash from the stored password
    salt = stored_password[:16]
    stored_hash = stored_password[16:]
    # Hash the provided password with the same salt
    hashed_password = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    # Compare the hashed password with the stored hash
    return hashed_password == stored_hash

def show_center_frame(email):
    # Clear other frames
    form_frame.pack_forget()
    login_frame.pack_forget()
    admin_frame.pack_forget()
    
    # Update window title
    app.title(f"{email} logged in")

    # Add a welcome message to the center frame
    tk.Label(center_frame, text=f"Welcome, {email}!", font=figma_font, bg=figma_bg_color).pack(pady=20)
    # Display the center frame
    center_frame.pack(expand=True, fill=tk.BOTH)

def validate_registration():
    first_name = first_name_entry.get()
    last_name = last_name_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    
    if len(first_name) <= 1 or not re.match("^[A-Za-z]+$", first_name):
        messagebox.showerror("Invalid Input", "First name must be more than one character and contain no special characters.")
        return
    
    if len(last_name) <= 1 or not re.match("^[A-Za-z]+$", last_name):
        messagebox.showerror("Invalid Input", "Last name must be more than one character and contain no special characters.")
        return
    
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        messagebox.showerror("Invalid Input", "Please enter a valid email address (e.g., df@dfg.com or gn@fgh.co.ca).")
        return
    
    if len(password) <= 1:
        messagebox.showerror("Invalid Input", "Password must be more than one character and not blank.")
        return
    
    # Save the data to the database
    save_to_database(first_name, last_name, email, password)

    # Show a success message 
    messagebox.showinfo("Success", "Registration successful!")
    show_center_frame(email)

def save_to_database(first_name, last_name, email, password):
    hashed_password = hash_password(password)
    with sqlite3.connect('my_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password BLOB NOT NULL  # Store as BLOB
        )
        ''')
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            messagebox.showerror("Invalid Input", "Email address already exists.")
            return
        cursor.execute('''
        INSERT INTO users (first_name, last_name, email, password)
        VALUES (?, ?, ?, ?)
        ''', (first_name, last_name, email, hashed_password))
        conn.commit()
    messagebox.showinfo("Success", f"Email {email} registered successfully!")

def show_form(form_to_show):
    form_frame.pack_forget()
    login_frame.pack_forget()
    admin_frame.pack_forget()
    center_frame.pack_forget()
    form_to_show.pack(pady=20)

def validate_login():
    email = login_email_entry.get()
    password = login_password_entry.get()

    with sqlite3.connect('my_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user:
            stored_password = user[4]  # Retrieve the stored password
            if check_password(stored_password, password):
                messagebox.showinfo("Success", f"Login successful! Logged in as: {email}")
                show_center_frame(email)
            else:
                messagebox.showerror("Invalid Input", "Invalid email or password.")
        else:
            messagebox.showerror("Invalid Input", "Invalid email or password.")

def validate_admin():
    admin_email = admin_email_entry.get()
    admin_password = admin_password_entry.get()

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", admin_email):
        messagebox.showerror("Invalid Input", "Please enter a valid email address (e.g., df@dfg.com or gn@fgh.co.ca).")
        return

    if len(admin_password) <= 1:
        messagebox.showerror("Invalid Input", "Password must be more than one character and not blank.")
        return

    # Add your admin validation logic here
    if admin_email == "pbg@pbg.com" and admin_password == "a123":
        messagebox.showinfo("Success", "Admin login successful!")
        show_center_frame(admin_email)
    else:
        messagebox.showerror("Invalid Input", "Invalid admin credentials.")

app.mainloop()
