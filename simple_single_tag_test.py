#!/usr/bin/env python3
"""
Simple Single Tag Test - Invisible NFC Scanning
Test the simplified single tag system with invisible input
"""

import sys
import termios
import tty
import hashlib
import json
from datetime import datetime

def invisible_input_capture():
    """Capture input invisibly without echo"""
    print("🔒 Waiting for NFC tag scan...")
    print("📱 Place tag on scanner (invisible mode)")
    print("⏱️  Input will not be displayed...")
    
    try:
        # Get file descriptor for stdin
        fd = sys.stdin.fileno()
        
        # Get current terminal settings
        old_settings = termios.tcgetattr(fd)
        
        # Set terminal to raw mode (no echo)
        tty.setraw(sys.stdin.fileno())
        
        # Capture input character by character
        uid_chars = []
        while True:
            char = sys.stdin.read(1)
            if char == '\n' or char == '\r':
                break
            uid_chars.append(char)
        
        # Restore original terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        
        uid_string = ''.join(uid_chars).strip()
        return uid_string
        
    except (ImportError, OSError) as e:
        # Fallback for systems without termios
        print("🔴 Using fallback input method")
        uid_string = input("Scan: ").strip()
        # Try to clear the echoed input
        print('\033[A\033[K', end='', flush=True)
        return uid_string

def test_single_tag_vault():
    """Test single tag credential vault system"""
    print("🔐 SINGLE NFC TAG VAULT TEST")
    print("=" * 35)
    print()
    
    # Get invisible NFC input
    nfc_uid = invisible_input_capture()
    
    if not nfc_uid:
        print("❌ No tag detected")
        return
    
    print()
    print("✅ TAG SCANNED SUCCESSFULLY")
    print("🔒 [UID Hidden for Security]")
    print(f"📊 Length: {len(nfc_uid)} characters")
    print()
    
    # Create single-tag vault
    print("🔐 CREATING SINGLE-TAG VAULT")
    print("-" * 30)
    
    # Use the single NFC UID as the master key
    master_key = hashlib.pbkdf2_hmac(
        'sha256',
        nfc_uid.encode(),
        b'single_tag_salt_2025',
        100000
    )
    
    # Google Cloud credentials
    gcp_credentials = {
        "type": "service_account",
        "project_id": "androidappmobileshield",
        "private_key_id": "3b7e5f89c1234567890abcdef1234567890abcde",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5W8aH...\n-----END PRIVATE KEY-----",
        "client_email": "nfc-auth-service@androidappmobileshield.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "universe_domain": "googleapis.com"
    }
    
    # Encrypt with single tag
    import base64
    creds_json = json.dumps(gcp_credentials, separators=(',', ':'))
    key_stream = (master_key * ((len(creds_json) // 32) + 1))[:len(creds_json)]
    encrypted_bytes = bytes(a ^ b for a, b in zip(creds_json.encode(), key_stream))
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    
    # Create vault
    vault_data = {
        "version": "4.0",
        "algorithm": "SINGLE-NFC-PBKDF2-XOR",
        "created": datetime.now().isoformat(),
        "nfc_tags_required": 1,
        "iterations": 100000,
        "salt": base64.b64encode(b'single_tag_salt_2025').decode(),
        "encrypted_payload": encrypted_b64,
        "checksum": hashlib.sha256(encrypted_b64.encode()).hexdigest()[:16],
        "metadata": {
            "project_id": gcp_credentials["project_id"],
            "service_account": gcp_credentials["client_email"],
            "vault_purpose": "Google Cloud Authentication"
        },
        "security": {
            "single_factor": True,
            "uid_exposure": "NONE",
            "runtime_assembly": True
        }
    }
    
    # Save vault
    with open("single_tag_vault.json", 'w') as f:
        json.dump(vault_data, f, indent=2)
    
    print("✅ Vault created with single NFC tag")
    print("🔐 Credentials encrypted successfully")
    print(f"📁 Saved: single_tag_vault.json")
    print()
    
    # Test decryption immediately
    print("🔓 TESTING DECRYPTION")
    print("-" * 25)
    
    # Recreate key from same UID
    test_key = hashlib.pbkdf2_hmac(
        'sha256',
        nfc_uid.encode(),
        base64.b64decode(vault_data['salt']),
        vault_data['iterations']
    )
    
    # Decrypt
    try:
        encrypted_data = base64.b64decode(vault_data['encrypted_payload'])
        key_stream = (test_key * ((len(encrypted_data) // 32) + 1))[:len(encrypted_data)]
        decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_data, key_stream))
        decrypted_creds = json.loads(decrypted_bytes.decode())
        
        print("✅ DECRYPTION SUCCESSFUL!")
        print(f"☁️  Project: {decrypted_creds['project_id']}")
        print("🔐 All credentials available for GCP auth")
        print()
        print("🎉 SINGLE TAG SYSTEM WORKING!")
        
    except Exception as e:
        print(f"❌ Decryption failed: {e}")

if __name__ == "__main__":
    test_single_tag_vault()
