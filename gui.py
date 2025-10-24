import bcrypt
import json
import os
import re
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib

class PasswordManager:
    def __init__(self, storage_file='passwords.json'):
        self.storage_file = storage_file
        self.users = self.load_users()

    def load_users(self):
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def save_users(self):
        with open(self.storage_file, 'w') as f:
            json.dump(self.users, f, indent=4)

    def check_password_strength(self, password):
        score = 0
        feedback = []

        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("• Password should be at least 8 characters")

        if len(password) >= 12:
            score += 1

        # Complexity checks
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("• Add uppercase letters")

        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("• Add lowercase letters")

        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("• Add numbers")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("• Add special characters (!@#$%^&*)")

        # Strength rating
        strength = ""
        color = ""
        if score <= 2:
            strength = "Weak"
            color = "red"
        elif score <= 4:
            strength = "Medium"
            color = "orange"
        else:
            strength = "Strong"
            color = "green"

        return score, strength, feedback, color

    def hash_password(self, password):
        # bcrypt automatically generates a unique salt for each password
        salt = bcrypt.gensalt(rounds=12)  # 12 rounds = 2^12 iterations
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self, password, hashed_password):
        return bcrypt.checkpw(
            password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )

    def register_user(self, username, password, email=""):
        # Check if user already exists
        if username in self.users:
            return False, "Username already exists!"

        # Check password strength
        score, strength, feedback, _ = self.check_password_strength(password)
        if score < 3:
            return False, f"Password too weak!\n" + "\n".join(feedback)

        # Hash the password
        hashed_pwd = self.hash_password(password)

        # Store user data
        self.users[username] = {
            'password_hash': hashed_pwd,
            'email': email,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_login': None
        }

        self.save_users()
        return True, f"User '{username}' registered successfully!\nPassword strength: {strength}"

    def authenticate_user(self, username, password):
        # Check if user exists
        if username not in self.users:
            return False, "Invalid username or password!"

        # Verify password
        user_data = self.users[username]
        if self.verify_password(password, user_data['password_hash']):
            # Update last login
            self.users[username]['last_login'] = datetime.now().strftime(
                '%Y-%m-%d %H:%M:%S')
            self.save_users()
            return True, f"Welcome back, {username}!"
        else:
            return False, "Invalid username or password!"

    def change_password(self, username, old_password, new_password):
        # Verify old password first
        success, _ = self.authenticate_user(username, old_password)
        if not success:
            return False, "Current password is incorrect!"

        # Check new password strength
        score, strength, feedback, _ = self.check_password_strength(
            new_password)
        if score < 3:
            return False, f"New password too weak!\n" + "\n".join(feedback)

        # Hash and update new password
        self.users[username]['password_hash'] = self.hash_password(
            new_password)
        self.save_users()
        return True, "Password changed successfully!"

    def get_user_info(self, username):
        if username in self.users:
            user_data = self.users[username].copy()
            # Remove sensitive data
            user_data.pop('password_hash', None)
            return user_data
        return None

    def demonstrate_hashing(self, password):
        result = []
        result.append("HASHING DEMONSTRATION")
        result.append("=" * 60)
        result.append(f"\nOriginal Password: {password}")
        result.append("\nGenerating 3 different hashes for the SAME password:")
        result.append(
            "(Notice how each hash is different due to unique salts)\n")

        for i in range(3):
            hashed = self.hash_password(password)
            result.append(f"\nHash #{i+1}:")
            result.append(f"  Full Hash: {hashed}")
            result.append(f"  Salt (embedded): {hashed[:29]}")
            result.append(f"  Length: {len(hashed)} characters")

        result.append("\n" + "=" * 60)
        result.append(
            "Each hash is unique because bcrypt generates a random salt!")
        result.append(
            "This is why the same password produces different hashes.")

        return "\n".join(result)


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Password Manager")
        self.root.geometry("700x600")
        self.root.configure(bg='#2C3E50')

        self.pm = PasswordManager()
        self.current_user = None

        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()

        # Create main container
        self.main_container = tk.Frame(root, bg='#2C3E50')
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.show_main_menu()

    def configure_styles(self):
        # Button styles
        self.style.configure('Main.TButton',
                             font=('Arial', 11, 'bold'),
                             padding=10,
                             background='#3498DB',
                             foreground='white')

        self.style.configure('Action.TButton',
                             font=('Arial', 10),
                             padding=8,
                             background='#27AE60')

        self.style.configure('Back.TButton',
                             font=('Arial', 10),
                             padding=8,
                             background='#95A5A6')

        # Label styles
        self.style.configure('Title.TLabel',
                             font=('Arial', 18, 'bold'),
                             background='#2C3E50',
                             foreground='#ECF0F1')

        self.style.configure('Subtitle.TLabel',
                             font=('Arial', 12),
                             background='#2C3E50',
                             foreground='#BDC3C7')

        self.style.configure('Info.TLabel',
                             font=('Arial', 10),
                             background='#34495E',
                             foreground='#ECF0F1')

    def clear_container(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()

    def logout(self):
        if self.current_user:
            messagebox.showinfo("Logout", f"Goodbye, {self.current_user}!")
            self.current_user = None
            self.show_main_menu()

    def show_main_menu(self):
        self.clear_container()
        # Don't reset current_user here - keep the logged-in state

        # Title
        title_frame = tk.Frame(self.main_container, bg='#2C3E50')
        title_frame.pack(pady=20)

        title = ttk.Label(title_frame, text="🔐 Secure Password Manager",
                          style='Title.TLabel')
        title.pack()

        subtitle = ttk.Label(title_frame,
                             text="Using bcrypt hashing with automatic salt generation",
                             style='Subtitle.TLabel')
        subtitle.pack(pady=5)

        # Show logged-in status
        if self.current_user:
            status_label = tk.Label(title_frame,
                                    text=f"✓ Logged in as: {self.current_user}",
                                    bg='#2C3E50', fg='#2ECC71',
                                    font=('Arial', 11, 'bold'))
            status_label.pack(pady=5)

        # Menu buttons
        button_frame = tk.Frame(self.main_container, bg='#2C3E50')
        button_frame.pack(pady=30)

        buttons = [
            ("👤 Register New User", self.show_register),
            ("🔓 Login (Authenticate)", self.show_login),
            ("🔑 Change Password", self.show_change_password),
            ("💪 Check Password Strength", self.show_password_strength),
            ("ℹ️  View User Info", self.show_user_info),
            ("🔬 Demonstrate Hashing & Salting", self.show_demo),
        ]

        # Add logout button if user is logged in, otherwise exit button
        if self.current_user:
            buttons.append(("🚪 Logout", self.logout))

        buttons.append(("❌ Exit", self.root.quit))

        for text, command in buttons:
            btn = tk.Button(button_frame, text=text, command=command,
                            font=('Arial', 11, 'bold'),
                            bg='#3498DB', fg='white',
                            width=35, height=2,
                            relief=tk.RAISED, bd=3,
                            cursor='hand2')
            btn.pack(pady=5)
            btn.bind('<Enter>', lambda e, b=btn: b.configure(bg='#2980B9'))
            btn.bind('<Leave>', lambda e, b=btn: b.configure(bg='#3498DB'))

    def show_register(self):
        self.clear_container()

        # Title
        title = ttk.Label(self.main_container, text="👤 User Registration",
                          style='Title.TLabel')
        title.pack(pady=20)

        # Form frame
        form_frame = tk.Frame(self.main_container,
                              bg='#34495E', relief=tk.RAISED, bd=2)
        form_frame.pack(pady=20, padx=50, fill=tk.BOTH)

        # Username
        tk.Label(form_frame, text="Username:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=20, pady=10)
        username_entry = tk.Entry(form_frame, font=('Arial', 10), width=30)
        username_entry.grid(row=0, column=1, padx=20, pady=10)

        # Email
        tk.Label(form_frame, text="Email (optional):", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky='w', padx=20, pady=10)
        email_entry = tk.Entry(form_frame, font=('Arial', 10), width=30)
        email_entry.grid(row=1, column=1, padx=20, pady=10)

        # Password
        tk.Label(form_frame, text="Password:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky='w', padx=20, pady=10)
        password_entry = tk.Entry(form_frame, font=(
            'Arial', 10), width=30, show='•')
        password_entry.grid(row=2, column=1, padx=20, pady=10)

        # Show password checkbox
        show_var = tk.BooleanVar()

        def toggle_password():
            password_entry.config(show='' if show_var.get() else '•')
            confirm_entry.config(show='' if show_var.get() else '•')

        tk.Checkbutton(form_frame, text="Show Password", variable=show_var,
                       command=toggle_password, bg='#34495E', fg='white',
                       selectcolor='#2C3E50').grid(row=2, column=2, padx=10)

        # Confirm Password
        tk.Label(form_frame, text="Confirm Password:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=3, column=0, sticky='w', padx=20, pady=10)
        confirm_entry = tk.Entry(form_frame, font=(
            'Arial', 10), width=30, show='•')
        confirm_entry.grid(row=3, column=1, padx=20, pady=10)

        # Buttons
        btn_frame = tk.Frame(self.main_container, bg='#2C3E50')
        btn_frame.pack(pady=20)

        def register():
            username = username_entry.get().strip()
            email = email_entry.get().strip()
            password = password_entry.get()
            confirm = confirm_entry.get()

            if not username or not password:
                messagebox.showerror(
                    "Error", "Username and password are required!")
                return

            if password != confirm:
                messagebox.showerror("Error", "Passwords don't match!")
                return

            success, message = self.pm.register_user(username, password, email)
            if success:
                messagebox.showinfo("Success", message)
                self.show_main_menu()
            else:
                messagebox.showerror("Error", message)

        tk.Button(btn_frame, text="✓ Register", command=register,
                  font=('Arial', 11, 'bold'), bg='#27AE60', fg='white',
                  width=15, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="← Back", command=self.show_main_menu,
                  font=('Arial', 11, 'bold'), bg='#95A5A6', fg='white',
                  width=15, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

    def show_login(self):
        self.clear_container()

        # Title
        title = ttk.Label(self.main_container, text="🔓 User Login",
                          style='Title.TLabel')
        title.pack(pady=20)

        # Form frame
        form_frame = tk.Frame(self.main_container,
                              bg='#34495E', relief=tk.RAISED, bd=2)
        form_frame.pack(pady=20, padx=100, fill=tk.BOTH)

        # Username
        tk.Label(form_frame, text="Username:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=20, pady=15)
        username_entry = tk.Entry(form_frame, font=('Arial', 10), width=30)
        username_entry.grid(row=0, column=1, padx=20, pady=15)

        # Password
        tk.Label(form_frame, text="Password:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky='w', padx=20, pady=15)
        password_entry = tk.Entry(form_frame, font=(
            'Arial', 10), width=30, show='•')
        password_entry.grid(row=1, column=1, padx=20, pady=15)

        # Show password
        show_var = tk.BooleanVar()
        tk.Checkbutton(form_frame, text="Show Password", variable=show_var,
                       command=lambda: password_entry.config(
                           show='' if show_var.get() else '•'),
                       bg='#34495E', fg='white', selectcolor='#2C3E50').grid(row=1, column=2, padx=10)

        # Buttons
        btn_frame = tk.Frame(self.main_container, bg='#2C3E50')
        btn_frame.pack(pady=20)

        def login():
            username = username_entry.get().strip()
            password = password_entry.get()

            if not username or not password:
                messagebox.showerror(
                    "Error", "Username and password are required!")
                return

            success, message = self.pm.authenticate_user(username, password)
            if success:
                self.current_user = username
                messagebox.showinfo("Success", message)
                self.show_main_menu()
            else:
                messagebox.showerror("Error", message)

        tk.Button(btn_frame, text="✓ Login", command=login,
                  font=('Arial', 11, 'bold'), bg='#27AE60', fg='white',
                  width=15, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="← Back", command=self.show_main_menu,
                  font=('Arial', 11, 'bold'), bg='#95A5A6', fg='white',
                  width=15, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

    def show_change_password(self):
        if not self.current_user:
            messagebox.showwarning("Warning", "Please login first!")
            return

        self.clear_container()

        # Title
        title = ttk.Label(self.main_container, text="🔑 Change Password",
                          style='Title.TLabel')
        title.pack(pady=20)

        tk.Label(self.main_container, text=f"Logged in as: {self.current_user}",
                 bg='#2C3E50', fg='#3498DB', font=('Arial', 11, 'bold')).pack()

        # Form frame
        form_frame = tk.Frame(self.main_container,
                              bg='#34495E', relief=tk.RAISED, bd=2)
        form_frame.pack(pady=20, padx=80, fill=tk.BOTH)

        # Current Password
        tk.Label(form_frame, text="Current Password:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=20, pady=10)
        current_entry = tk.Entry(form_frame, font=(
            'Arial', 10), width=30, show='•')
        current_entry.grid(row=0, column=1, padx=20, pady=10)

        # New Password
        tk.Label(form_frame, text="New Password:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky='w', padx=20, pady=10)
        new_entry = tk.Entry(form_frame, font=(
            'Arial', 10), width=30, show='•')
        new_entry.grid(row=1, column=1, padx=20, pady=10)

        # Confirm New Password
        tk.Label(form_frame, text="Confirm New Password:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky='w', padx=20, pady=10)
        confirm_entry = tk.Entry(form_frame, font=(
            'Arial', 10), width=30, show='•')
        confirm_entry.grid(row=2, column=1, padx=20, pady=10)

        # Show password
        show_var = tk.BooleanVar()

        def toggle_passwords():
            show = '' if show_var.get() else '•'
            current_entry.config(show=show)
            new_entry.config(show=show)
            confirm_entry.config(show=show)

        tk.Checkbutton(form_frame, text="Show Passwords", variable=show_var,
                       command=toggle_passwords, bg='#34495E', fg='white',
                       selectcolor='#2C3E50').grid(row=2, column=2, padx=10)

        # Buttons
        btn_frame = tk.Frame(self.main_container, bg='#2C3E50')
        btn_frame.pack(pady=20)

        def change():
            current = current_entry.get()
            new = new_entry.get()
            confirm = confirm_entry.get()

            if not current or not new:
                messagebox.showerror("Error", "All fields are required!")
                return

            if new != confirm:
                messagebox.showerror("Error", "New passwords don't match!")
                return

            success, message = self.pm.change_password(
                self.current_user, current, new)
            if success:
                messagebox.showinfo("Success", message)
                self.show_main_menu()
            else:
                messagebox.showerror("Error", message)

        tk.Button(btn_frame, text="✓ Change Password", command=change,
                  font=('Arial', 11, 'bold'), bg='#27AE60', fg='white',
                  width=18, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="← Back", command=self.show_main_menu,
                  font=('Arial', 11, 'bold'), bg='#95A5A6', fg='white',
                  width=15, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

    def show_password_strength(self):
        self.clear_container()

        # Title
        title = ttk.Label(self.main_container, text="💪 Password Strength Checker",
                          style='Title.TLabel')
        title.pack(pady=20)

        # Input frame
        input_frame = tk.Frame(self.main_container,
                               bg='#34495E', relief=tk.RAISED, bd=2)
        input_frame.pack(pady=20, padx=100, fill=tk.X)

        tk.Label(input_frame, text="Enter password to test:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).pack(pady=10)

        password_entry = tk.Entry(input_frame, font=(
            'Arial', 11), width=40, show='•')
        password_entry.pack(pady=10)

        show_var = tk.BooleanVar()
        tk.Checkbutton(input_frame, text="Show Password", variable=show_var,
                       command=lambda: password_entry.config(
                           show='' if show_var.get() else '•'),
                       bg='#34495E', fg='white', selectcolor='#2C3E50').pack(pady=5)

        # Result frame
        result_frame = tk.Frame(self.main_container,
                                bg='#34495E', relief=tk.SUNKEN, bd=2)
        result_frame.pack(pady=20, padx=100, fill=tk.BOTH, expand=True)

        strength_label = tk.Label(result_frame, text="", bg='#34495E',
                                  font=('Arial', 14, 'bold'), pady=10)
        strength_label.pack()

        score_label = tk.Label(result_frame, text="", bg='#34495E', fg='white',
                               font=('Arial', 11))
        score_label.pack()

        feedback_text = scrolledtext.ScrolledText(result_frame, height=8, width=50,
                                                  font=('Arial', 10), bg='#2C3E50',
                                                  fg='white', wrap=tk.WORD)
        feedback_text.pack(pady=10, padx=20)

        def check():
            password = password_entry.get()
            if not password:
                messagebox.showwarning("Warning", "Please enter a password!")
                return

            score, strength, feedback, color = self.pm.check_password_strength(
                password)

            strength_label.config(
                text=f"Password Strength: {strength}", fg=color)
            score_label.config(text=f"Score: {score}/6")

            feedback_text.delete(1.0, tk.END)
            if feedback:
                feedback_text.insert(
                    tk.END, "Suggestions for improvement:\n\n")
                for tip in feedback:
                    feedback_text.insert(tk.END, f"{tip}\n")
            else:
                feedback_text.insert(
                    tk.END, "✓ Excellent password!\n\nYour password meets all requirements.")

        # Buttons
        btn_frame = tk.Frame(self.main_container, bg='#2C3E50')
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="✓ Check Strength", command=check,
                  font=('Arial', 11, 'bold'), bg='#27AE60', fg='white',
                  width=18, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="← Back", command=self.show_main_menu,
                  font=('Arial', 11, 'bold'), bg='#95A5A6', fg='white',
                  width=15, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

    def show_user_info(self):
        if not self.current_user:
            messagebox.showwarning("Warning", "Please login first!")
            return

        self.clear_container()

        # Title
        title = ttk.Label(self.main_container, text="ℹ️  User Information",
                          style='Title.TLabel')
        title.pack(pady=20)

        # Info frame
        info_frame = tk.Frame(self.main_container,
                              bg='#34495E', relief=tk.RAISED, bd=3)
        info_frame.pack(pady=20, padx=100, fill=tk.BOTH, expand=True)

        info = self.pm.get_user_info(self.current_user)
        if info:
            info['username'] = self.current_user

            tk.Label(info_frame, text=f"User Profile: {self.current_user}",
                     bg='#34495E', fg='#3498DB',
                     font=('Arial', 14, 'bold')).pack(pady=15)

            details_frame = tk.Frame(info_frame, bg='#34495E')
            details_frame.pack(pady=10, padx=30, fill=tk.BOTH, expand=True)

            row = 0
            for key, value in info.items():
                label_text = key.replace('_', ' ').title() + ":"
                tk.Label(details_frame, text=label_text, bg='#34495E', fg='#ECF0F1',
                         font=('Arial', 11, 'bold'), anchor='w').grid(row=row, column=0,
                                                                      sticky='w', pady=8, padx=10)
                tk.Label(details_frame, text=str(value) if value else "N/A",
                         bg='#34495E', fg='#BDC3C7',
                         font=('Arial', 11), anchor='w').grid(row=row, column=1,
                                                              sticky='w', pady=8, padx=10)
                row += 1

        # Button
        tk.Button(self.main_container, text="← Back", command=self.show_main_menu,
                  font=('Arial', 11, 'bold'), bg='#95A5A6', fg='white',
                  width=15, height=2, cursor='hand2').pack(pady=20)

    def show_demo(self):
        self.clear_container()

        # Title
        title = ttk.Label(self.main_container, text="🔬 Hashing & Salting Demonstration",
                          style='Title.TLabel')
        title.pack(pady=20)

        # Input frame
        input_frame = tk.Frame(self.main_container,
                               bg='#34495E', relief=tk.RAISED, bd=2)
        input_frame.pack(pady=10, padx=100, fill=tk.X)

        tk.Label(input_frame, text="Enter a test password:", bg='#34495E', fg='white',
                 font=('Arial', 10, 'bold')).pack(pady=10)

        password_entry = tk.Entry(input_frame, font=('Arial', 11), width=40)
        password_entry.pack(pady=10)

        # Result frame
        result_frame = tk.Frame(self.main_container, bg='#2C3E50')
        result_frame.pack(pady=10, padx=50, fill=tk.BOTH, expand=True)

        result_text = scrolledtext.ScrolledText(result_frame, height=18, width=70,
                                                font=('Courier', 9), bg='#1C2833',
                                                fg='#00FF00', wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True)

        def demonstrate():
            password = password_entry.get()
            if not password:
                messagebox.showwarning("Warning", "Please enter a password!")
                return

            result = self.pm.demonstrate_hashing(password)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, result)

        # Buttons
        btn_frame = tk.Frame(self.main_container, bg='#2C3E50')
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="✓ Demonstrate", command=demonstrate,
                  font=('Arial', 11, 'bold'), bg='#E67E22', fg='white',
                  width=18, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="← Back", command=self.show_main_menu,
                  font=('Arial', 11, 'bold'), bg='#95A5A6', fg='white',
                  width=15, height=2, cursor='hand2').pack(side=tk.LEFT, padx=10)


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
