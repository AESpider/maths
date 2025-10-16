#!/usr/bin/env python3
"""
ECB Oracle Server - Simulates a vulnerable encryption service
Runs on localhost:1337 and appends a secret to each message (flag)
"""

import socket
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Configuration
HOST = 'localhost'
PORT = 1337
SECRET_FLAG = b'FLAG{f4k3_f0r_t3st1ng}'
AES_KEY = os.urandom(16)  # Random 128-bit key

def encrypt_ecb(plaintext):
    """Encrypts plaintext + flag using AES-ECB mode"""
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    
    # Pad and encrypt the combined message
    padded_data = pad(plaintext + SECRET_FLAG, AES.block_size)
    return cipher.encrypt(padded_data)

def handle_client(conn, addr):
    """Handles a single client connection"""
    print(f"[+] Connection from {addr}")
    
    try:
        while True:
            # Receive message from client
            data = conn.recv(1024)
            if not data:
                break
            
            # Remove newline and process
            message = data.strip()
            
            # Encrypt message + flag
            ciphertext = encrypt_ecb(message)
            
            # Send base64-encoded response
            response = base64.b64encode(ciphertext) + b'\n'
            conn.sendall(response)
            
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()
        print(f"[-] Connection closed {addr}")

def start_server():
    """Starts the ECB oracle server"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        
        print(f"[*] ECB Oracle Server started on {HOST}:{PORT}")
        print(f"[*] Secret flag: {SECRET_FLAG.decode()}")
        print(f"[*] Waiting for connections...")
        
        try:
            while True:
                conn, addr = s.accept()
                handle_client(conn, addr)
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")

if __name__ == "__main__":
    start_server()