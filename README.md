# 🔐 Secure Password Manager

A password manager application that implements secure password handling using cryptographic hashing with salt generation.

## 📋 Project Overview

This project demonstrates secure credential storage and verification with:

### 1️⃣ Using Bcrypt
- **Bcrypt hashing** with 12 rounds (2^12 iterations)
- **Automatic salt generation** for each password
- Industry-standard security practices
- **Files**: `main.py`, `gui.py`

### 2️⃣ Custom Hashing and salt
- **Custom hash function** (no bcrypt/hashlib)
- **Manual salt generation** using random bytes
- **Key stretching** with 10,000 iterations
- Demonstrates cryptographic principles
- **Files**: `gui_custom_hash.py`

## ✨ Features

- ✅ User Registration with email
- ✅ Secure Login/Authentication
- ✅ Password Change Functionality
- ✅ Real-time Password Strength Checker
- ✅ User Profile Management
- ✅ Hashing & Salting Demonstration
- ✅ Both CLI and GUI interfaces

## 🛠️ Setup Instructions

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/bajoriya-vaibhav/Cyber_Security_Project.git
cd Cyber_Security_Project
```

2. **Install required dependencies**

**For bcrypt version (gui.py / main.py):**
```bash
pip install bcrypt
```

**For custom hash version (gui_custom_hash.py):**
```bash
# No dependencies needed! Pure Python implementation
```

## 🚀 How to Run

### 🔷 Production Version (bcrypt)

**GUI Version (Recommended):**
```bash
python gui.py
```

**CLI Version:**
```bash
python main.py
```

### 🔶 Custom Hash - No Dependencies!

**GUI Version:**
```bash
python gui_custom_hash.py
```

This version implements everything from scratch without bcrypt or hashlib!

## 🧪 Testing the Application

### Test Scenario 1: Register a New User
1. Launch the application
2. Click **"Register New User"** (GUI) or select option `1` (CLI)
3. Enter username: `testuser`
4. Enter email: `test@example.com`
5. Enter a strong password (e.g., `SecurePass@123`)
6. Confirm the password
7. ✅ Registration successful!

### Test Scenario 2: Login
1. Click **"Login (Authenticate)"** or select option `2`
2. Enter username: `testuser`
3. Enter password: `SecurePass@123`
4. ✅ Login successful! (GUI shows logged-in status)

### Test Scenario 3: Check Password Strength
1. Click **"Check Password Strength"** or select option `4`
2. Test different passwords:
   - Weak: `abc123` (Score: 2/6)
   - Medium: `Password123` (Score: 4/6)
   - Strong: `MyP@ssw0rd!2024` (Score: 6/6)
3. ✅ View strength rating and improvement suggestions

### Test Scenario 4: Demonstrate Hashing
1. Click **"Demonstrate Hashing & Salting"** or select option `6`
2. Enter a test password: `test123`
3. ✅ Observe 3 different hashes generated for the same password
4. Notice how each hash is unique due to random salt generation

### Test Scenario 5: Change Password
1. Make sure you're logged in
2. Click **"Change Password"** or select option `3`
3. Enter current password
4. Enter new strong password
5. Confirm new password
6. ✅ Password updated successfully!

### Test Scenario 6: View User Info
1. Make sure you're logged in
2. Click **"View User Info"** or select option `5`
3. ✅ View your profile (username, email, created date, last login)

## 📁 Project Structure

```
CyberSecurity_project/
│
├── main.py                      # CLI version (bcrypt)
├── gui.py                       # GUI version (bcrypt)
├── gui_custom_hash.py          # GUI with custom hash (no dependencies!)
├── passwords.json               # Password storage for bcrypt version
├── passwords_custom.json        # Password storage for custom hash version
├── README.md                    # Project documentations
└── LICENSE                      # License file
```

## 🔒 Security Features

### Password Requirements
- Minimum 8 characters (12+ recommended)
- Must contain uppercase letters (A-Z)
- Must contain lowercase letters (a-z)
- Must contain numbers (0-9)
- Must contain special characters (!@#$%^&*)
- Minimum score: 3/6 to register

### Hashing Details

**Production Version (bcrypt):**
- **Algorithm**: bcrypt (Blowfish cipher)
- **Cost Factor**: 12 rounds (4,096 iterations)
- **Salt**: Automatically generated (unique per password)
- **Hash Length**: 60 characters
- **Format**: `$2b$12$[22-char salt][31-char hash]`

**Custom Version (from scratch):**
- **Algorithm**: Custom hash function (SHA-256 inspired)
- **Iterations**: 10,000 rounds (key stretching)
- **Salt**: 16 random bytes (manually generated)
- **Hash Length**: 32 bytes (256 bits)
- **Format**: `iterations$salt_hex$hash_hex`

## 💾 Data Storage

User credentials are stored in JSON files with the following structure:

**bcrypt version** (`passwords.json`):
```json
{
  "username": {
    "password_hash": "$2b$12$...",
    "email": "user@example.com",
    "created_at": "2025-10-24 10:30:00",
    "last_login": "2025-10-24 11:45:00"
  }
}
```

**Custom version** (`passwords_custom.json`):
```json
{
  "username": {
    "password_hash": "10000$a3b5c7d9...$9f3e5d7c...",
    "email": "user@example.com",
    "created_at": "2025-10-24 10:30:00",
    "last_login": "2025-10-24 11:45:00"
  }
}
```

**Note**: Only password hashes are stored, never plain-text passwords!

## 🎯 Key Concepts Demonstrated

1. **Salt**: Random data added to passwords before hashing (prevents rainbow tables)
2. **Hashing**: One-way cryptographic function (irreversible)
3. **Key Stretching**: Multiple hash iterations (slows brute force attacks)
4. **bcrypt**: Industry-standard adaptive hash function for passwords
5. **Custom Implementation**: Understanding cryptographic principles from scratch
6. **Verification**: Comparing hashes instead of plain-text passwords
7. **Constant-Time Comparison**: Prevents timing attacks

## � Learn More

### Understanding the Custom Implementation

For a deep dive into how the custom hash implementation works (without bcrypt/hashlib), check out:
📖 **[CUSTOM_HASH_EXPLANATION.md](CUSTOM_HASH_EXPLANATION.md)**

This document explains:
- How the custom hash function works
- Salt generation from scratch
- Key stretching implementation
- Attack resistance mechanisms
- Comparison with bcrypt
- Why to use established libraries in production

## 🔄 Which Version Should You Use?

### Use **bcrypt version** (`gui.py` / `main.py`) when:
- ✅ Building for production
- ✅ Need battle-tested security
- ✅ Want industry-standard practices
- ✅ Security is critical

### Use **custom version** (`gui_custom_hash.py`) when:
- 📚 Learning cryptographic principles
- 🔬 Understanding how hashing works
- 🎓 Educational demonstrations
- 🧪 Experimenting with concepts

**⚠️ Important**: Never use the custom implementation in production!

## �📝 License

This project is open source and available under the MIT License.