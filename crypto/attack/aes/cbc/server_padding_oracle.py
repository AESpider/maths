#!/usr/bin/env python3
"""
Vulnerable server demonstrating CBC padding oracle vulnerability
"""

import base64
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify

app = Flask(__name__)
HOST, PORT = "localhost", 1337
BLOCK_SIZE = 16

# Store keys and messages per user
user_keys = {}
user_messages = {}

def generate_key_for_user(username):
    """Generate deterministic AES key from username hash"""
    if username not in user_keys:
        hash_obj = hashlib.sha256(username.encode())
        user_keys[username] = hash_obj.digest()[:16]
    return user_keys[username]

def generate_message_for_user(username):
    """Generate secret message containing user flag"""
    if username not in user_messages:
        flag = f"FLAG{{{hash(username) % 999999999}}}"
        user_messages[username] = f"Congratulations {username}! Here is your flag: {flag}".encode()
    return user_messages[username]

def aes_cbc_encrypt(plaintext, key):
    """Encrypt plaintext using AES-CBC with random IV"""
    iv = os.urandom(BLOCK_SIZE)
    padded_plaintext = pad(plaintext, BLOCK_SIZE, style='pkcs7')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv, ciphertext

def aes_cbc_decrypt(iv, ciphertext, key):
    """Decrypt ciphertext and validate PKCS#7 padding"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(padded_plaintext, BLOCK_SIZE, style='pkcs7')
        return plaintext, True
    except ValueError:
        return None, False

@app.route('/api/encrypt', methods=['POST'])
def encrypt_message():
    """
    Encrypt user message and return ciphertext
    Request: {"username": "string"}
    Response: {"iv": "base64", "ciphertext": "base64"}
    """
    try:
        data = request.get_json()
        if not data or 'username' not in data:
            return jsonify({"error": "Missing 'username' field"}), 400
        
        username = data['username']
        
        if len(username) < 1:
            return jsonify({"error": "Username must be at least 1 character"}), 400
        
        key = generate_key_for_user(username)
        message = generate_message_for_user(username)
        iv, ciphertext = aes_cbc_encrypt(message, key)
        
        iv_b64 = base64.b64encode(iv).decode()
        ct_b64 = base64.b64encode(ciphertext).decode()
        
        print(f"[INFO] Encrypted message for user: {username}")
        
        return jsonify({"iv": iv_b64, "ciphertext": ct_b64})
        
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify_padding', methods=['POST'])
def verify_padding():
    """
    Verify if decrypted ciphertext has valid PKCS#7 padding
    Request: {"iv": "base64", "ciphertext": "base64", "username": "string"}
    Response: {"valid": boolean}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data"}), 400
        
        required_fields = ['iv', 'ciphertext', 'username']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing '{field}' field"}), 400
        
        username = data['username']
        
        if username not in user_keys:
            return jsonify({"error": "Unknown user - call /api/encrypt first"}), 400
        
        key = user_keys[username]
        iv = base64.b64decode(data['iv'])
        ciphertext = base64.b64decode(data['ciphertext'])
        
        if len(iv) != BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE != 0:
            return jsonify({"valid": False})
        
        _, is_valid = aes_cbc_decrypt(iv, ciphertext, key)
        
        return jsonify({"valid": is_valid})
        
    except Exception as e:
        print(f"[ERROR] Verification failed: {e}")
        return jsonify({"valid": False})

@app.route('/status', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "running",
        "users": len(user_keys),
        "service": "CBC Padding Oracle"
    })

@app.route('/', methods=['GET'])
def home():
    """Service information page"""
    return """
    <h1>CBC Padding Oracle Service</h1>
    <p>Available endpoints:</p>
    <ul>
        <li><code>POST /api/encrypt</code> - Encrypt user message</li>
        <li><code>POST /api/verify_padding</code> - Verify padding validity</li>
        <li><code>GET /status</code> - Service status check</li>
    </ul>
    """

if __name__ == '__main__':
    print("-" * 60)
    print(f"Starting server on http://{HOST}:{PORT}")
    print("Endpoints: /api/encrypt, /api/verify_padding, /status")
    app.run(host=HOST, port=PORT, debug=True)