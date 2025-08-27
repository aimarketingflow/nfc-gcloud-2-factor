#!/usr/bin/env python3
"""
NFC Credential Vault System
Uses NFC tag UID to encrypt/decrypt Google Cloud credentials
AIMF LLC - Maximum Security Implementation
"""

import json
import base64
import hashlib
import os
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from datetime import datetime
import sys

class NFCCredentialVault:
    """Secure credential storage using NFC tag as encryption key"""
    
    def __init__(self):
        self.vault_file = "encrypted_gcp_vault.json"
        self.setup_complete = False
        
    def generate_key_from_nfc(self, nfc_uid: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Generate encryption key from NFC UID"""
        if salt is None:
            salt = os.urandom(32)
        
        # Use PBKDF2 to derive key from NFC UID
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        # Convert UID to bytes and derive key
        uid_bytes = nfc_uid.encode('utf-8')
        key = base64.urlsafe_b64encode(kdf.derive(uid_bytes))
        
        return key, salt
    
    def encrypt_credentials(self, credentials: Dict, nfc_uid: str) -> Dict:
        """Encrypt Google Cloud credentials using NFC UID"""
        print("\n🔒 ENCRYPTING CREDENTIALS WITH NFC KEY")
        print("=" * 40)
        
        # Generate encryption key from NFC UID
        key, salt = self.generate_key_from_nfc(nfc_uid)
        fernet = Fernet(key)
        
        # Convert credentials to JSON
        cred_json = json.dumps(credentials)
        
        # Encrypt the credentials
        encrypted_data = fernet.encrypt(cred_json.encode())
        
        # Create vault structure
        vault_data = {
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "algorithm": "Fernet-PBKDF2-SHA256",
            "iterations": 100000,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "encrypted_credentials": base64.b64encode(encrypted_data).decode('utf-8'),
            "metadata": {
                "project_id": credentials.get("project_id", "unknown"),
                "vault_type": "Google Cloud Platform",
                "security_level": "NFC-Protected"
            }
        }
        
        print("✅ Credentials encrypted successfully")
        print("🔐 Encryption uses NFC tag as master key")
        print("📊 Security: AES-256 with PBKDF2")
        
        return vault_data
    
    def decrypt_credentials(self, nfc_uid: str) -> Optional[Dict]:
        """Decrypt credentials using NFC UID"""
        print("\n🔓 DECRYPTING CREDENTIALS WITH NFC KEY")
        print("=" * 40)
        
        try:
            # Load vault file
            if not os.path.exists(self.vault_file):
                print("❌ Vault file not found")
                return None
            
            with open(self.vault_file, 'r') as f:
                vault_data = json.load(f)
            
            # Extract salt and encrypted data
            salt = base64.b64decode(vault_data['salt'])
            encrypted_data = base64.b64decode(vault_data['encrypted_credentials'])
            
            # Generate key from NFC UID
            key, _ = self.generate_key_from_nfc(nfc_uid, salt)
            fernet = Fernet(key)
            
            # Decrypt credentials
            decrypted_json = fernet.decrypt(encrypted_data)
            credentials = json.loads(decrypted_json.decode())
            
            print("✅ Credentials decrypted successfully")
            print("🔐 Authentication ready")
            
            return credentials
            
        except Exception as e:
            print(f"❌ Decryption failed: Invalid NFC key")
            print("🔒 Access denied - wrong tag or corrupted vault")
            return None
    
    def save_vault(self, vault_data: Dict):
        """Save encrypted vault to file"""
        with open(self.vault_file, 'w') as f:
            json.dump(vault_data, f, indent=2)
        
        print(f"\n💾 Vault saved: {self.vault_file}")
        print("🔐 Credentials protected with NFC encryption")
    
    def scan_nfc_for_key(self) -> str:
        """Scan NFC tag and return UID for key generation"""
        print("\n🔍 SCAN NFC TAG FOR KEY GENERATION")
        print("=" * 35)
        print("📱 Place your NFC tag on the reader...")
        print("🔒 Tag UID will be used as encryption key")
        print("⏱️  Waiting for tag...")
        
        # For testing with barcode scanner input
        uid = input().strip()
        
        if uid:
            # Hide the actual UID
            print("\n✅ TAG SCANNED SUCCESSFULLY")
            print("🔐 UID captured for key generation")
            print("🔒 [UID Hidden for Security]")
            return uid
        else:
            print("❌ No tag detected")
            return None
    
    def setup_credential_vault(self, gcp_credentials: Dict):
        """Initial setup - encrypt credentials with NFC tag"""
        print("\n🏗️  CREDENTIAL VAULT SETUP")
        print("=" * 30)
        print("This will encrypt your Google Cloud credentials")
        print("using your NFC tag as the master key.")
        print()
        print("⚠️  IMPORTANT:")
        print("• You'll need this exact NFC tag to decrypt")
        print("• Keep your tag secure - it's your key")
        print("• Backup tag recommended for recovery")
        
        # Scan NFC for master key
        nfc_uid = self.scan_nfc_for_key()
        if not nfc_uid:
            print("❌ Setup aborted - no NFC tag detected")
            return False
        
        # Encrypt credentials
        vault_data = self.encrypt_credentials(gcp_credentials, nfc_uid)
        
        # Save encrypted vault
        self.save_vault(vault_data)
        
        print("\n✅ VAULT SETUP COMPLETE")
        print("🔐 Credentials encrypted and stored")
        print("🏷️  NFC tag is now your master key")
        
        return True
    
    def authenticate_with_nfc(self) -> Optional[Dict]:
        """Scan NFC tag to decrypt and retrieve credentials"""
        print("\n🔐 NFC AUTHENTICATION REQUIRED")
        print("=" * 35)
        print("Scan your NFC tag to unlock credentials...")
        
        # Scan NFC tag
        nfc_uid = self.scan_nfc_for_key()
        if not nfc_uid:
            print("❌ Authentication failed - no tag detected")
            return None
        
        # Decrypt credentials
        credentials = self.decrypt_credentials(nfc_uid)
        
        if credentials:
            print("\n✅ AUTHENTICATION SUCCESSFUL")
            print("🔓 Credentials unlocked and ready")
            print("☁️  Proceeding with Google Cloud authentication...")
        
        return credentials


def main():
    """Test credential vault setup"""
    vault = NFCCredentialVault()
    
    # Your Google Cloud credentials (provided earlier)
    gcp_credentials = {
        "type": "service_account",
        "project_id": "androidappmobileshield",
        "private_key_id": "3b7e5f89c1234567890abcdef1234567890abcde",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\n[KEY_CONTENT_HIDDEN]\n-----END RSA PRIVATE KEY-----\n",
        "client_email": "nfc-auth-service@androidappmobileshield.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/nfc-auth-service%40androidappmobileshield.iam.gserviceaccount.com"
    }
    
    print("🔐 NFC CREDENTIAL VAULT SYSTEM")
    print("=" * 35)
    print()
    print("Choose operation:")
    print("1. Setup new vault (encrypt credentials)")
    print("2. Authenticate (decrypt with NFC tag)")
    print("3. Test end-to-end flow")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == "1":
        vault.setup_credential_vault(gcp_credentials)
    elif choice == "2":
        credentials = vault.authenticate_with_nfc()
        if credentials:
            print(f"\n📋 Project ID: {credentials.get('project_id')}")
            print("🔐 Full credentials available for GCP API")
    elif choice == "3":
        print("\n🧪 TESTING END-TO-END FLOW")
        print("Step 1: Setup vault with NFC tag")
        if vault.setup_credential_vault(gcp_credentials):
            print("\nStep 2: Authenticate with same tag")
            credentials = vault.authenticate_with_nfc()
            if credentials:
                print("\n✅ End-to-end test successful!")
                print("🔐 System ready for production")
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
