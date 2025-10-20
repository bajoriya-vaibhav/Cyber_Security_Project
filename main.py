import bcrypt
import json
import os
import re
import getpass
from datetime import datetime
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
            feedback.append("!! Password should be at least 8 characters")
        
        if len(password) >= 12:
            score += 1
        
        # Complexity checks
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("!! Add uppercase letters")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("!! Add lowercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("!! Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("!! Add special characters (!@#$%^&*)")
        
        # Strength rating
        strength = ""
        if score <= 2:
            strength = "Weak :<"
        elif score <= 4:
            strength = "Medium :|"
        else:
            strength = "Strong :)"
        
        return score, strength, feedback
    
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
            return False, "!! Username already exists!"
        
        # Check password strength
        score, strength, feedback = self.check_password_strength(password)
        if score < 3:
            return False, f"!! Password too weak!\n" + "\n".join(feedback)
        
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
            return False, "!! Invalid username or password!"
        
        # Verify password
        user_data = self.users[username]
        if self.verify_password(password, user_data['password_hash']):
            # Update last login
            self.users[username]['last_login'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.save_users()
            return True, f"Welcome back, {username}!"
        else:
            return False, "!! Invalid username or password!"
    
    def change_password(self, username, old_password, new_password):
        # Verify old password first
        success, _ = self.authenticate_user(username, old_password)
        if not success:
            return False, "!! Current password is incorrect!"
        
        # Check new password strength
        score, strength, feedback = self.check_password_strength(new_password)
        if score < 3:
            return False, f"!! New password too weak!\n" + "\n".join(feedback)
        
        # Hash and update new password
        self.users[username]['password_hash'] = self.hash_password(new_password)
        self.save_users()
        return True, f"Password changed successfully!"
    
    def get_user_info(self, username):
        if username in self.users:
            user_data = self.users[username].copy()
            # Remove sensitive data
            user_data.pop('password_hash', None)
            return user_data
        return None
    
    def demonstrate_hashing(self, password):
        print("\nHASHING DEMONSTRATION\n")
        print(f"Original Password: {password}")
        print("\nGenerating 3 different hashes for the SAME password:")
        print("(Notice how each hash is different due to unique salts)\n")
        
        for i in range(3):
            hashed = self.hash_password(password)
            print(f"Hash #{i+1}:")
            print(f"  Full Hash: {hashed}")
            print(f"  Salt (embedded): {hashed[:29]}")
            print(f"  Length: {len(hashed)} characters")
            print()
        
        print("Each hash is unique because bcrypt generates a random salt!\n")


def print_menu():
    print("SECURE PASSWORD MANAGER:-")
    print("1. Register New User")
    print("2. Login (Authenticate)")
    print("3. Change Password")
    print("4. Check Password Strength")
    print("5. View User Info")
    print("6. Demonstrate Hashing & Salting")
    print("7. Exit")

def main():
    pm = PasswordManager()
    current_user = None
    
    print("\n Welcome to Secure Password Manager!")
    print("This system uses bcrypt hashing with automatic salt generation.")
    
    while True:
        print_menu()
        choice = input("\nEnter your choice (1-7): ").strip()
        
        if choice == '1':
            # Register new user
            print("\n--- USER REGISTRATION ---")
            username = input("Enter username: ").strip()
            email = input("Enter email (optional): ").strip()
            password = getpass.getpass("Enter password: ")
            confirm_pwd = getpass.getpass("Confirm password: ")
            
            if password != confirm_pwd:
                print("!!Passwords don't match!")
                continue
            
            success, message = pm.register_user(username, password, email)
            print(f"\n{message}")
        
        elif choice == '2':
            # Login
            print("\n--- USER LOGIN ---")
            username = input("Enter username: ").strip()
            password = getpass.getpass("Enter password: ")
            
            success, message = pm.authenticate_user(username, password)
            print(f"\n{message}")
            if success:
                current_user = username
        
        elif choice == '3':
            # Change password
            if not current_user:
                print("\n!! Please login first!")
                continue
            
            print("\n--- CHANGE PASSWORD ---")
            old_pwd = getpass.getpass("Enter current password: ")
            new_pwd = getpass.getpass("Enter new password: ")
            confirm_pwd = getpass.getpass("Confirm new password: ")
            
            if new_pwd != confirm_pwd:
                print("!! New passwords don't match!")
                continue
            
            success, message = pm.change_password(current_user, old_pwd, new_pwd)
            print(f"\n{message}")
        
        elif choice == '4':
            # Check password strength
            print("\n--- PASSWORD STRENGTH CHECKER ---")
            test_pwd = getpass.getpass("Enter password to test: ")
            score, strength, feedback = pm.check_password_strength(test_pwd)
            
            print(f"\n Password Strength: {strength}")
            print(f"Score: {score}/6")
            if feedback:
                print("\nSuggestions for improvement:")
                for tip in feedback:
                    print(f"  {tip}")
        
        elif choice == '5':
            # View user info
            if not current_user:
                print("\n!! Please login first!")
                continue
            
            print("\n--- USER INFORMATION ---")
            info = pm.get_user_info(current_user)
            info['username']=current_user
            if info:
                for key, value in info.items():
                    print(f"{key.replace('_', ' ').title()}: {value}")
        
        elif choice == '6':
            # Demonstrate hashing
            test_pwd = input("\nEnter a test password to demonstrate hashing: ")
            pm.demonstrate_hashing(test_pwd)
        
        elif choice == '7':
            # Exit
            print("\n Thank you for using Secure Password Manager!")
            print("Stay secure! 🔐")
            break
        
        else:
            print("\n!! Invalid choice! Please try again.")

if __name__ == "__main__":
    main()