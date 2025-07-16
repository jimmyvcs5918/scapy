from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from passlib.hash import argon2
import json
import os
from zxcvbn import zxcvbn

app = Flask(__name__)

# --- Configuration (IMPORTANT: In a real app, manage these securely) ---
# For demonstration: Generate a secret key for Fernet encryption
# In a real app, this key should be securely stored and loaded,
# perhaps derived from the master password or a securely managed key.
try:
    with open("secret.key", "rb") as key_file:
        ENCRYPTION_KEY = key_file.read()
except FileNotFoundError:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(ENCRYPTION_KEY)

CIPHER_SUITE = Fernet(ENCRYPTION_KEY)
DATABASE_FILE = 'passwords.json'
MASTER_PASSWORD_HASH_FILE = 'master_hash.json'

# --- Helper Functions ---

def load_data(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return {}

def save_data(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def encrypt_password(password):
    return CIPHER_SUITE.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return CIPHER_SUITE.decrypt(encrypted_password.encode()).decode()

def hash_master_password(password):
    return argon2.hash(password)

def verify_master_password(password_hash, password_attempt):
    try:
        return argon2.verify(password_attempt, password_hash)
    except Exception:
        return False

# --- Backend API Endpoints ---

@app.route('/register', methods=['POST'])
def register_master_password():
    data = request.json
    master_password = data.get('master_password')

    if not master_password:
        return jsonify({"message": "Master password is required"}), 400

    if os.path.exists(MASTER_PASSWORD_HASH_FILE):
        return jsonify({"message": "Master password already set. Please log in."}), 409

    master_hash = hash_master_password(master_password)
    save_data({"master_hash": master_hash}, MASTER_PASSWORD_HASH_FILE)
    return jsonify({"message": "Master password registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    master_password = data.get('master_password')

    if not master_password:
        return jsonify({"message": "Master password is required"}), 400

    master_data = load_data(MASTER_PASSWORD_HASH_FILE)
    stored_master_hash = master_data.get('master_hash')

    if not stored_master_hash or not verify_master_password(stored_master_hash, master_password):
        return jsonify({"message": "Invalid master password"}), 401

    return jsonify({"message": "Login successful"}), 200

@app.route('/passwords', methods=['GET'])
def get_passwords():
    # In a real app, you'd need authentication for every endpoint
    # This example assumes login was successful
    passwords_data = load_data(DATABASE_FILE)
    decrypted_passwords = []
    for entry in passwords_data.get('accounts', []):
        try:
            decrypted_passwords.append({
                "id": entry.get("id"),
                "website": entry.get("website"),
                "username": entry.get("username"),
                "password": decrypt_password(entry.get("password")) # Decrypt for display
            })
        except Exception as e:
            print(f"Error decrypting password: {e}")
            # Handle decryption errors gracefully, maybe log them

    return jsonify({"passwords": decrypted_passwords}), 200

@app.route('/passwords', methods=['POST'])
def add_password():
    data = request.json
    website = data.get('website')
    username = data.get('username')
    password = data.get('password')

    if not all([website, username, password]):
        return jsonify({"message": "Website, username, and password are required"}), 400

    encrypted_password = encrypt_password(password)
    passwords_data = load_data(DATABASE_FILE)
    accounts = passwords_data.get('accounts', [])
    new_id = len(accounts) + 1 # Simple ID generation
    accounts.append({
        "id": new_id,
        "website": website,
        "username": username,
        "password": encrypted_password
    })
    passwords_data['accounts'] = accounts
    save_data(passwords_data, DATABASE_FILE)

    return jsonify({"message": "Password added successfully", "id": new_id}), 201

@app.route('/password/strength', methods=['POST'])
def check_password_strength():
    data = request.json
    password = data.get('password')

    if not password:
        return jsonify({"message": "Password is required"}), 400

    # Use zxcvbn for comprehensive password strength analysis
    strength_result = zxcvbn(password)

    # Score: 0-4 (0=worst, 4=best)
    # Suggestions: Advice on how to improve the password
    return jsonify({
        "password": password,
        "score": strength_result['score'],
        "feedback": strength_result['feedback'],
        "suggestions": strength_result['feedback']['suggestions']
    }), 200

@app.route('/password/generate', methods=['POST'])
def generate_strong_password():
    # Simple password generation for demonstration.
    # A more "AI-powered" version might learn from user preferences
    # or generate pronounceable but strong passwords.
    import secrets
    import string

    length = request.json.get('length', 16)
    if not isinstance(length, int) or length < 8:
        length = 16

    characters = string.ascii_letters + string.digits + string.punctuation
    generated_password = ''.join(secrets.choice(characters) for i in range(length))

    return jsonify({"generated_password": generated_password}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)