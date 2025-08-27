#!/usr/bin/env python3
"""
gcloud auth nfc - Dual NFC verification for Google Cloud authentication
Requires two NFC tags for enhanced security

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import os
import json
import hashlib
import pickle
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
except ImportError:
    print("❌ pyscard not available - install with: pip install pyscard")
    exit(1)

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
except ImportError:
    print("❌ cryptography not available - install with: pip install cryptography")
    exit(1)

class DualNFCAuthenticator:
    """Dual NFC tag authentication for enhanced security"""
    
    def __init__(self):
        self.vault_dir = Path.home() / ".nfc_vault" / "gcloud"
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        
        self.chaos_vault = "../.chaos_vault"
        self.encrypted_creds = self.vault_dir / "encrypted_gcloud_creds.vault"
        self.vault_metadata = self.vault_dir / "vault_metadata.json"
        
        # gcloud credential paths
        self.gcloud_dir = Path.home() / ".config" / "gcloud"
        self.adc_file = self.gcloud_dir / "application_default_credentials.json"
    
    def read_nfc_tag(self, tag_name: str) -> Optional[bytes]:
        """Read NFC tag with user prompts"""
        if not readers:
            print("❌ No NFC readers available")
            return None
        
        try:
            reader_list = readers()
            if not reader_list:
                print("❌ No NFC readers detected")
                return None
            
            reader = reader_list[0]
            print(f"🔍 Using: {reader}")
            
            input(f"📱 Place {tag_name} on reader and press Enter...")
            
            connection = reader.createConnection()
            connection.connect()
            
            # Read card UID
            response, sw1, sw2 = connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            
            if sw1 == 0x90 and sw2 == 0x00:
                uid_data = bytes(response)
                print(f"✅ {tag_name} read successfully")
                return uid_data
            else:
                print(f"❌ Failed to read {tag_name}: {sw1:02X} {sw2:02X}")
                return None
                
        except Exception as e:
            print(f"❌ NFC error: {e}")
            return None
    
    def verify_against_vault(self, nfc_data: bytes) -> bool:
        """Verify NFC data against chaos vault"""
        try:
            if os.path.exists(self.chaos_vault):
                with open(self.chaos_vault, 'rb') as f:
                    vault = pickle.load(f)
                    
                for stored_value in vault.get("chaos_values", []):
                    if stored_value == nfc_data:
                        return True
        except Exception:
            pass
        return False
    
    def dual_nfc_authentication(self) -> Optional[bytes]:
        """Perform dual NFC authentication"""
        print("🔐 Dual NFC Authentication Required")
        print("   Two NFC tags needed for Google Cloud access")
        print()
        
        # Read first NFC tag
        nfc1_data = self.read_nfc_tag("PRIMARY NFC tag")
        if not nfc1_data:
            return None
        
        if not self.verify_against_vault(nfc1_data):
            print("❌ Primary NFC verification failed")
            return None
        
        print("✅ Primary NFC verified")
        print()
        
        # Read second NFC tag
        nfc2_data = self.read_nfc_tag("SECONDARY NFC tag")
        if not nfc2_data:
            return None
        
        if not self.verify_against_vault(nfc2_data):
            print("❌ Secondary NFC verification failed")
            return None
        
        print("✅ Secondary NFC verified")
        print()
        
        # Combine both NFC values for encryption key
        combined_data = nfc1_data + nfc2_data + b"dual_nfc_2024"
        combined_hash = hashlib.sha256(combined_data).digest()
        
        print("🔑 Dual NFC authentication successful!")
        return combined_hash
    
    def derive_encryption_key(self, dual_nfc_hash: bytes) -> bytes:
        """Derive Fernet encryption key from dual NFC hash"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'gcloud_dual_nfc_vault',
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(dual_nfc_hash))
        return key
    
    def encrypt_and_store_credentials(self, service_account_path: str, dual_nfc_hash: bytes) -> bool:
        """Encrypt service account JSON with dual NFC key"""
        try:
            # Load service account JSON
            with open(service_account_path, 'r') as f:
                credentials = json.load(f)
            
            # Encrypt credentials
            encryption_key = self.derive_encryption_key(dual_nfc_hash)
            fernet = Fernet(encryption_key)
            
            creds_bytes = json.dumps(credentials).encode()
            encrypted_creds = fernet.encrypt(creds_bytes)
            
            # Save encrypted credentials
            with open(self.encrypted_creds, 'wb') as f:
                f.write(encrypted_creds)
            
            # Create metadata
            metadata = {
                "created_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(days=7)).isoformat(),
                "dual_nfc_fingerprint": hashlib.sha256(dual_nfc_hash).hexdigest()[:16],
                "original_sa_file": service_account_path
            }
            
            with open(self.vault_metadata, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"✅ Credentials encrypted with dual NFC key")
            print(f"   Expires: {metadata['expires_at'][:19]}")
            
            return True
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return False
    
    def decrypt_and_setup_gcloud(self, dual_nfc_hash: bytes) -> bool:
        """Decrypt credentials and set up gcloud"""
        try:
            # Check if vault exists
            if not self.encrypted_creds.exists():
                print("❌ No encrypted credentials found")
                print("   Run: gcloud auth nfc --setup /path/to/service-account.json")
                return False
            
            # Load metadata
            with open(self.vault_metadata, 'r') as f:
                metadata = json.load(f)
            
            # Check expiration
            expires_at = datetime.fromisoformat(metadata['expires_at'])
            if datetime.now() > expires_at:
                print("❌ Credentials expired (7 days)")
                print("   Re-run setup: gcloud auth nfc --setup /path/to/service-account.json")
                self.cleanup_expired()
                return False
            
            # Verify dual NFC fingerprint
            fingerprint = hashlib.sha256(dual_nfc_hash).hexdigest()[:16]
            if fingerprint != metadata['dual_nfc_fingerprint']:
                print("❌ Dual NFC verification failed")
                return False
            
            # Decrypt credentials
            encryption_key = self.derive_encryption_key(dual_nfc_hash)
            fernet = Fernet(encryption_key)
            
            with open(self.encrypted_creds, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_bytes = fernet.decrypt(encrypted_data)
            credentials = json.loads(decrypted_bytes.decode())
            
            # Set up gcloud ADC
            self.gcloud_dir.mkdir(parents=True, exist_ok=True)
            with open(self.adc_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            
            print("🎉 Google Cloud authentication successful!")
            print(f"   Valid until: {metadata['expires_at'][:19]}")
            print(f"   Project: {credentials.get('project_id', 'N/A')}")
            print()
            print("✅ You can now use gcloud commands:")
            print("   gcloud storage buckets list")
            print("   gcloud compute instances list")
            print("   gcloud projects list")
            
            return True
            
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            return False
    
    def cleanup_expired(self):
        """Clean up expired credentials"""
        try:
            if self.encrypted_creds.exists():
                self.encrypted_creds.unlink()
            if self.vault_metadata.exists():
                self.vault_metadata.unlink()
            if self.adc_file.exists():
                self.adc_file.unlink()
            print("🧹 Expired credentials cleaned up")
        except Exception as e:
            print(f"⚠️  Cleanup error: {e}")

def main():
    """Main CLI interface"""
    import sys
    
    print("🔷 gcloud auth nfc - Dual NFC Authentication")
    print("   AIMF LLC - MobileShield NFC Chaos Writer")
    print()
    
    auth = DualNFCAuthenticator()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--setup" and len(sys.argv) > 2:
            sa_path = sys.argv[2]
            if not os.path.exists(sa_path):
                print(f"❌ Service account file not found: {sa_path}")
                exit(1)
            
            print("🔐 Setting up dual NFC encrypted credential vault...")
            dual_nfc_hash = auth.dual_nfc_authentication()
            
            if dual_nfc_hash:
                success = auth.encrypt_and_store_credentials(sa_path, dual_nfc_hash)
                if success:
                    print("✅ Setup complete! Use 'gcloud auth nfc' to authenticate")
                else:
                    exit(1)
            else:
                exit(1)
                
        elif sys.argv[1] == "--cleanup":
            auth.cleanup_expired()
            print("✅ Cleanup complete")
            
        else:
            print("Usage:")
            print("  gcloud auth nfc                              - Authenticate with dual NFC")
            print("  gcloud auth nfc --setup service-account.json - Set up encrypted vault")
            print("  gcloud auth nfc --cleanup                    - Clean up expired credentials")
    
    else:
        # Standard authentication
        dual_nfc_hash = auth.dual_nfc_authentication()
        
        if dual_nfc_hash:
            auth.decrypt_and_setup_gcloud(dual_nfc_hash)
        else:
            print("❌ Dual NFC authentication failed")
            exit(1)

if __name__ == "__main__":
    main()
