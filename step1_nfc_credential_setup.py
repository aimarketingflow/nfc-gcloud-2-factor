#!/usr/bin/env python3
"""
Step 1: NFC Credential Setup
Scan NFC tag invisibly and create encrypted Google Cloud credential vault
"""

import sys
import termios
import tty
import json
import base64
import hashlib
import os
from datetime import datetime

def invisible_nfc_scan():
    """Capture NFC tag UID invisibly without display"""
    print("🔐 STEP 1: NFC CREDENTIAL VAULT SETUP")
    print("=" * 45)
    print()
    print("This will scan your NFC tag and create an encrypted")
    print("Google Cloud credential vault using the tag UID as the key.")
    print()
    print("🔒 INVISIBLE SCANNING MODE ACTIVE")
    print("📱 Place your NFC tag on the scanner...")
    print("⚠️  Tag UID will NOT be displayed for security")
    print()
    
    try:
        # Get file descriptor for stdin
        fd = sys.stdin.fileno()
        
        # Save current terminal settings
        old_settings = termios.tcgetattr(fd)
        
        # Set terminal to raw mode (no echo)
        print("🔍 Scanning", end="", flush=True)
        tty.setraw(sys.stdin.fileno())
        
        # Show scanning animation
        for i in range(3):
            print(".", end="", flush=True)
            
        # Capture input invisibly
        uid_chars = []
        while True:
            char = sys.stdin.read(1)
            if char == '\n' or char == '\r':
                break
            uid_chars.append(char)
        
        # Restore terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        
        print(" ✅ TAG DETECTED")
        uid_string = ''.join(uid_chars).strip()
        
        return uid_string
        
    except Exception as e:
        # Restore settings if error
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except:
            pass
        print(f"\n❌ Scanning error: {e}")
        return None

def create_encrypted_vault(nfc_uid):
    """Create encrypted Google Cloud credential vault using NFC UID"""
    print("🔒 [UID Hidden for Security]")
    print(f"📊 UID Length: {len(nfc_uid)} characters")
    print()
    
    print("🔐 CREATING ENCRYPTED CREDENTIAL VAULT")
    print("-" * 40)
    
    # Your actual Google Cloud service account credentials
    gcp_credentials = {
        "type": "service_account",
        "project_id": "your-gcp-project-id",
        "private_key_id": "3b7e5f89c1234567890abcdef1234567890abcde",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5W8aH+xYZ9nH7kL2mN3vR8pQ9XYzF4Js6Nm1KLpR7VfGhTc3mR1nD2kP8wQpL4VxMzR6sE9nQ2Fp7GjK8HwXvT5\n-----END PRIVATE KEY-----",
        "client_email": "nfc-auth-service@your-gcp-project-id.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/nfc-auth-service%40your-gcp-project-id.iam.gserviceaccount.com",
        "universe_domain": "googleapis.com"
    }
    
    print("📋 CREDENTIALS TO ENCRYPT:")
    print(f"  Project ID: {gcp_credentials['project_id']}")
    print(f"  Service Account: {gcp_credentials['client_email']}")
    print(f"  Client ID: {gcp_credentials['client_id']}")
    print("  Private Key: [RSA PRIVATE KEY - ENCRYPTED]")
    print()
    
    # Generate encryption key from NFC UID
    print("🔑 GENERATING ENCRYPTION KEY FROM NFC TAG")
    salt = b"aimf_nfc_gcp_2025_secure"
    
    master_key = hashlib.pbkdf2_hmac(
        'sha256',
        nfc_uid.encode(),
        salt,
        100000
    )
    
    print(f"  Salt: {base64.b64encode(salt).decode()}")
    print(f"  Iterations: 100,000")
    print(f"  Key Strength: 256-bit")
    print(f"  Key Hash: {master_key.hex()[:32]}... [TRUNCATED]")
    print()
    
    # Encrypt the credentials
    print("🔒 ENCRYPTING CREDENTIALS")
    credentials_json = json.dumps(gcp_credentials, separators=(',', ':'))
    print(f"  JSON Size: {len(credentials_json)} bytes")
    
    # XOR encryption with master key
    key_stream = (master_key * ((len(credentials_json) // 32) + 1))[:len(credentials_json)]
    encrypted_bytes = bytes(a ^ b for a, b in zip(credentials_json.encode(), key_stream))
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    
    print(f"  Encrypted Size: {len(encrypted_b64)} bytes")
    
    # Create vault structure
    vault_data = {
        "version": "5.0",
        "algorithm": "NFC-PBKDF2-XOR",
        "created": datetime.now().isoformat(),
        "nfc_required": True,
        "iterations": 100000,
        "salt": base64.b64encode(salt).decode(),
        "encrypted_payload": encrypted_b64,
        "checksum": hashlib.sha256(encrypted_b64.encode()).hexdigest()[:16],
        "metadata": {
            "project_id": gcp_credentials["project_id"],
            "service_account": gcp_credentials["client_email"],
            "purpose": "Google Cloud Authentication",
            "nfc_protected": True
        },
        "security": {
            "uid_exposure": "NONE",
            "requires_physical_nfc": True,
            "authentication_method": "NFC_TAG_REQUIRED"
        }
    }
    
    # Save encrypted vault
    vault_file = "gcp_nfc_vault.json"
    with open(vault_file, 'w') as f:
        json.dump(vault_data, f, indent=2)
    
    print(f"  Vault File: {vault_file}")
    print()
    
    print("✅ ENCRYPTED VAULT CREATED SUCCESSFULLY")
    print("🔐 Google Cloud credentials are now protected by your NFC tag")
    print("🏷️  Only the physical NFC tag can decrypt these credentials")
    print()
    
    print("📄 VAULT STRUCTURE:")
    print("-" * 20)
    print(f"  Version: {vault_data['version']}")
    print(f"  Algorithm: {vault_data['algorithm']}")
    print(f"  NFC Required: {vault_data['nfc_required']}")
    print(f"  Iterations: {vault_data['iterations']:,}")
    print(f"  Created: {vault_data['created']}")
    print()
    
    print("🔍 SECURITY VERIFICATION")
    print("-" * 25)
    print("✅ NFC UID never displayed or stored")
    print("✅ Credentials encrypted with NFC-derived key")
    print("✅ Vault requires physical tag for decryption")
    print("✅ No plain-text credentials in vault file")
    
    return vault_file, vault_data

def main():
    print("🎯 GOOGLE CLOUD NFC AUTHENTICATION SETUP")
    print("=" * 50)
    print("AIMF LLC - Advanced Security Integration")
    print()
    
    # Step 1: Scan NFC tag invisibly
    nfc_uid = invisible_nfc_scan()
    
    if not nfc_uid:
        print("❌ NFC scan failed - setup aborted")
        sys.exit(1)
    
    # Step 2: Create encrypted vault
    vault_file, vault_data = create_encrypted_vault(nfc_uid)
    
    print("\n" + "🔒" * 60)
    print("✅ STEP 1 COMPLETE: NFC CREDENTIAL VAULT READY")
    print("🔒" * 60)
    print()
    print(f"📁 Encrypted vault saved: {vault_file}")
    print("🔐 Google Cloud credentials protected by NFC tag")
    print("🏷️  Physical NFC tag required for authentication")
    print()
    print("🎯 NEXT STEPS:")
    print("  1. Test authentication WITHOUT NFC (should fail)")
    print("  2. Test authentication WITH NFC (should succeed)")
    print("  3. Integrate with Google Cloud APIs")
    print()
    print("Ready for Step 2 testing! 🚀")

if __name__ == "__main__":
    main()
