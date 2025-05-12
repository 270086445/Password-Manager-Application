import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import random
import string
from cryptography.fernet import Fernet
import os
import base64

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x600")

        # Encryption setup
        self.key_file = 'secret.key'
        self.data_file = 'passwords.json'
        self.load_or_generate_key()

        # Create main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Add this to your __init__ method before creating widgets
        style = ttk.Style()
        style.theme_use('clam')  # Try 'alt', 'default', 'classic', 'vista' (Windows)

        # Configure colors
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TButton', background='#4a7a8c', foreground='white')
        style.configure('TLabel', background='#f0f0f0', foreground='#333333')
        style.configure('Treeview', background='white', fieldbackground='white')

        # Create widgets
        self.create_widgets()

        # Load data
        self.load_data()



    def load_or_generate_key(self):
        """Load encryption key or generate a new one if it doesn't exist"""
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as key_file:
                key_file.write(key)
        else:
            with open(self.key_file, 'rb') as key_file:
                key = key_file.read()

        self.cipher_suite = Fernet(key)

    def encrypt_data(self, data):
        """Encrypt data before storing"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher_suite.encrypt(data).decode()

    def decrypt_data(self, encrypted_data):
        """Decrypt data for use"""
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode()
        return self.cipher_suite.decrypt(encrypted_data).decode()

    def create_widgets(self):
        """Create all GUI widgets"""
        # Top buttons frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=5)

        # Buttons
        self.add_button = ttk.Button(button_frame, text="Add Password", command=self.add_password)
        self.add_button.pack(side=tk.LEFT, padx=5)

        self.edit_button = ttk.Button(button_frame, text="Edit", command=self.edit_password)
        self.edit_button.pack(side=tk.LEFT, padx=5)

        self.delete_button = ttk.Button(button_frame, text="Delete", command=self.delete_password)
        self.delete_button.pack(side=tk.LEFT, padx=5)

        self.generate_button = ttk.Button(button_frame, text="Generate Password", command=self.generate_password)
        self.generate_button.pack(side=tk.LEFT, padx=5)

        self.refresh_button = ttk.Button(button_frame, text="Refresh", command=self.load_data)
        self.refresh_button.pack(side=tk.LEFT, padx=5)



        # Search frame
        search_frame = ttk.Frame(self.main_frame)
        search_frame.pack(fill=tk.X, pady=5)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind('<KeyRelease>', self.search_passwords)

        # Treeview to display passwords
        self.tree = ttk.Treeview(self.main_frame, columns=('Website', 'Username', 'Password'), show='headings')
        self.tree.heading('Website', text='Website/App')
        self.tree.heading('Username', text='Username/Email')
        self.tree.heading('Password', text='Password')

        self.tree.column('Website', width=250)
        self.tree.column('Username', width=250)
        self.tree.column('Password', width=200)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind double click to show password
        self.tree.bind('<Double-1>', self.show_password)

    def add_password(self):
        """Add a new password entry"""
        dialog = PasswordDialog(self.root, "Add Password")
        if dialog.result:
            website, username, password = dialog.result

            # Encrypt the password before storing
            encrypted_password = self.encrypt_data(password)

            self.passwords.append({
                'website': website,
                'username': username,
                'password': encrypted_password
            })

            self.save_data()
            self.load_data()

    def edit_password(self):
        """Edit selected password entry"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a password to edit")
            return

        item = self.tree.item(selected[0])
        website = item['values'][0]
        username = item['values'][1]

        # Find the password in our data
        for pwd in self.passwords:
            if pwd['website'] == website and pwd['username'] == username:
                # Decrypt the password for editing
                decrypted_password = self.decrypt_data(pwd['password'])

                dialog = PasswordDialog(
                    self.root,
                    "Edit Password",
                    website,
                    username,
                    decrypted_password
                )

                if dialog.result:
                    new_website, new_username, new_password = dialog.result

                    # Update the entry
                    pwd['website'] = new_website
                    pwd['username'] = new_username
                    pwd['password'] = self.encrypt_data(new_password)

                    self.save_data()
                    self.load_data()
                break

    def delete_password(self):
        """Delete selected password entry"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a password to delete")
            return

        item = self.tree.item(selected[0])
        website = item['values'][0]
        username = item['values'][1]

        # Confirm deletion
        if messagebox.askyesno("Confirm", f"Delete password for {website} - {username}?"):
            # Find and remove the password
            self.passwords = [pwd for pwd in self.passwords
                            if not (pwd['website'] == website and pwd['username'] == username)]

            self.save_data()
            self.load_data()

    def generate_password(self):
        """Generate a strong random password"""
        length = simpledialog.askinteger("Password Length", "Enter password length (8-64):",
                                        minvalue=8, maxvalue=64, initialvalue=16)
        if length:
            chars = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(chars) for _ in range(length))

            # Show the generated password
            messagebox.showinfo("Generated Password", f"Your new password:\n\n{password}")

    def show_password(self, event):
        """Show the selected password in a messagebox"""
        selected = self.tree.selection()
        if selected:
            item = self.tree.item(selected[0])
            website = item['values'][0]
            username = item['values'][1]
            encrypted_password = item['values'][2]

            # Find and decrypt the password
            for pwd in self.passwords:
                if pwd['website'] == website and pwd['username'] == username:
                    decrypted_password = self.decrypt_data(pwd['password'])
                    messagebox.showinfo(
                        "Password Details",
                        f"Website/App: {website}\nUsername/Email: {username}\nPassword: {decrypted_password}"
                    )
                    break

    def search_passwords(self, event=None):
        """Filter passwords based on search term"""
        search_term = self.search_entry.get().lower()

        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add items that match search
        for pwd in self.passwords:
            if (search_term in pwd['website'].lower() or
                search_term in pwd['username'].lower()):

                # Display asterisks for password in the treeview
                self.tree.insert('', tk.END, values=(
                    pwd['website'],
                    pwd['username'],
                    '********'
                ))

    def load_data(self):
        """Load password data from file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    self.passwords = json.load(f)
            else:
                self.passwords = []

            # Clear current items
            for item in self.tree.get_children():
                self.tree.delete(item)

            # Add items to treeview
            for pwd in self.passwords:
                # Display asterisks for password in the treeview
                self.tree.insert('', tk.END, values=(
                    pwd['website'],
                    pwd['username'],
                    '********'
                ))

            # Clear search
            self.search_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load data: {str(e)}")
            self.passwords = []

    def save_data(self):
        """Save password data to file"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.passwords, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save data: {str(e)}")

class PasswordDialog(tk.Toplevel):
    """Dialog for adding/editing passwords"""
    def __init__(self, parent, title, website="", username="", password=""):
        super().__init__(parent)
        self.title(title)
        self.geometry("400x250")
        self.resizable(False, False)

        self.result = None

        # Create widgets
        ttk.Label(self, text="Website/App:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.website_entry = ttk.Entry(self, width=30)
        self.website_entry.grid(row=0, column=1, padx=5, pady=5)
        self.website_entry.insert(0, website)

        ttk.Label(self, text="Username/Email:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.username_entry = ttk.Entry(self, width=30)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        self.username_entry.insert(0, username)

        ttk.Label(self, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(self, width=30, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        self.password_entry.insert(0, password)

        # Show password checkbox
        self.show_password_var = tk.IntVar()
        self.show_password_check = ttk.Checkbutton(
            self,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_check.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

        # Buttons
        button_frame = ttk.Frame(self)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="OK", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT, padx=5)

        self.transient(parent)
        self.grab_set()
        self.wait_window(self)

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def on_ok(self):
        """Handle OK button click"""
        website = self.website_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not website or not username or not password:
            messagebox.showwarning("Warning", "All fields are required")
            return

        self.result = (website, username, password)
        self.destroy()

    def on_cancel(self):
        """Handle Cancel button click"""
        self.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()