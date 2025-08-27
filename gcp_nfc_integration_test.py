#!/usr/bin/env python3
"""
Google Cloud NFC Integration - Complete Test Suite
Step-by-step testing: Setup -> Fail Without NFC -> Success With NFC
"""

import sys
import termios
import tty
import json
import base64
import hashlib
import os
from datetime import datetime

class GoogleCloudNFCAuth:
    def __init__(self):
        self.vault_file = "gcp_nfc_vault.json"
        self.nfc_uid = None
        
    def invisible_nfc_scan(self, step_name):
        """Capture NFC tag UID invisibly"""
        print(f"🔍 {step_name} - NFC SCANNING")
        print("-" * 40)
        print("📱 Place NFC tag on scanner...")
        print("🔒 Invisible mode - UID will not be displayed")
        print("⏱️  Waiting for input...")
        
        try:
            # Get terminal file descriptor
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            
            # Set raw mode (no echo)
            tty.setraw(sys.stdin.fileno())
            
            # Capture input invisibly
            uid_chars = []
            while True:
                char = sys.stdin.read(1)
                if char in ['\n', '\r']:
                    break
                uid_chars.append(char)
            
            # Restore terminal
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
            uid = ''.join(uid_chars).strip()
            
            if uid:
                print("✅ NFC TAG DETECTED")
                print("🔒 [UID Hidden for Security]")
                print(f"📊 Length: {len(uid)} characters")
                return uid
            else:
                print("❌ No tag data received")
                return None
                
        except Exception as e:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except:
                pass
            print(f"❌ Scan error: {e}")
            return None
    
    def step1_setup_vault(self):
        """Step 1: Scan NFC and create encrypted vault"""
        print("🎯 STEP 1: CREATE NFC-ENCRYPTED CREDENTIAL VAULT")
        print("=" * 55)
        print()
        
        # Scan NFC tag
        self.nfc_uid = self.invisible_nfc_scan("VAULT CREATION")
        
        if not self.nfc_uid:
            print("❌ Step 1 failed - no NFC tag detected")
            return False
        
        print()
        print("🔐 CREATING ENCRYPTED VAULT")
        print("-" * 30)
        
        # Google Cloud credentials to encrypt
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
        
        print(f"📋 Encrypting credentials for: {gcp_credentials['project_id']}")
        
        # Generate encryption key from NFC UID
        salt = b"gcp_nfc_2025_secure"
        master_key = hashlib.pbkdf2_hmac(
            'sha256',
            self.nfc_uid.encode(),
            salt,
            100000
        )
        
        print(f"🔑 Generated 256-bit key from NFC tag")
        print(f"⚙️  PBKDF2 iterations: 100,000")
        
        # Encrypt credentials
        creds_json = json.dumps(gcp_credentials, separators=(',', ':'))
        key_stream = (master_key * ((len(creds_json) // 32) + 1))[:len(creds_json)]
        encrypted_bytes = bytes(a ^ b for a, b in zip(creds_json.encode(), key_stream))
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
        
        # Create vault
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
                "service_account": gcp_credentials["client_email"]
            }
        }
        
        # Save vault
        with open(self.vault_file, 'w') as f:
            json.dump(vault_data, f, indent=2)
        
        print(f"💾 Vault saved: {self.vault_file}")
        print("✅ STEP 1 COMPLETE: Vault created and encrypted")
        
        return True
    
    def step2_test_without_nfc(self):
        """Step 2: Test authentication WITHOUT NFC (should fail)"""
        print("\n🎯 STEP 2: TEST AUTHENTICATION WITHOUT NFC")
        print("=" * 50)
        print("Testing that system blocks access without physical NFC tag")
        print()
        
        if not os.path.exists(self.vault_file):
            print("❌ No vault file found - run Step 1 first")
            return False
        
        # Load vault
        with open(self.vault_file, 'r') as f:
            vault_data = json.load(f)
        
        print("📁 Vault loaded successfully")
        print(f"🔐 Algorithm: {vault_data['algorithm']}")
        print(f"🏷️  Requires NFC: {vault_data['nfc_required']}")
        print()
        
        print("🚫 ATTEMPTING AUTHENTICATION WITHOUT NFC TAG")
        print("-" * 45)
        print("Trying to decrypt credentials without NFC...")
        
        # Try to decrypt with dummy/wrong key (should fail)
        try:
            dummy_key = hashlib.pbkdf2_hmac(
                'sha256',
                b"wrong_dummy_key",
                base64.b64decode(vault_data['salt']),
                vault_data['iterations']
            )
            
            encrypted_data = base64.b64decode(vault_data['encrypted_payload'])
            key_stream = (dummy_key * ((len(encrypted_data) // 32) + 1))[:len(encrypted_data)]
            decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_data, key_stream))
            
            # Try to parse as JSON (should fail)
            credentials = json.loads(decrypted_bytes.decode())
            
            print("❌ SECURITY BREACH - Decryption should have failed!")
            return False
            
        except Exception:
            print("✅ ACCESS DENIED - Authentication blocked without NFC")
            print("🔒 Vault properly secured - cannot decrypt without tag")
            print("✅ STEP 2 COMPLETE: Security verification passed")
            return True
    
    def step3_test_with_nfc(self):
        """Step 3: Test authentication WITH NFC (should succeed)"""
        print("\n🎯 STEP 3: TEST AUTHENTICATION WITH NFC")
        print("=" * 48)
        print("Testing that system grants access with correct NFC tag")
        print()
        
        # Scan NFC tag for authentication
        auth_nfc_uid = self.invisible_nfc_scan("AUTHENTICATION")
        
        if not auth_nfc_uid:
            print("❌ Step 3 failed - no NFC tag for authentication")
            return False
        
        print()
        print("🔓 ATTEMPTING AUTHENTICATION WITH NFC TAG")
        print("-" * 45)
        
        # Load vault
        with open(self.vault_file, 'r') as f:
            vault_data = json.load(f)
        
        try:
            # Generate key from scanned NFC UID
            master_key = hashlib.pbkdf2_hmac(
                'sha256',
                auth_nfc_uid.encode(),
                base64.b64decode(vault_data['salt']),
                vault_data['iterations']
            )
            
            # Decrypt credentials
            encrypted_data = base64.b64decode(vault_data['encrypted_payload'])
            key_stream = (master_key * ((len(encrypted_data) // 32) + 1))[:len(encrypted_data)]
            decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_data, key_stream))
            
            # Parse credentials
            credentials = json.loads(decrypted_bytes.decode())
            
            print("✅ DECRYPTION SUCCESSFUL!")
            print("🔓 Google Cloud credentials reassembled")
            print()
            print("📋 AUTHENTICATED CREDENTIALS:")
            print(f"  ☁️  Project ID: {credentials.get('project_id')}")
            print(f"  🔐 Service Account: {credentials.get('client_email')}")
            print(f"  🗝️  Client ID: {credentials.get('client_id')}")
            print("  🔑 Private Key: [AVAILABLE IN MEMORY]")
            print()
            print("🚀 READY FOR GOOGLE CLOUD API AUTHENTICATION!")
            print("✅ STEP 3 COMPLETE: NFC authentication successful")
            
            return True
            
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            print("🔒 Wrong NFC tag or corrupted vault")
            return False
    
    def run_complete_test(self):
        """Run the complete 3-step test suite"""
        print("🔐 GOOGLE CLOUD NFC AUTHENTICATION - COMPLETE TEST")
        print("=" * 60)
        print("AIMF LLC - Advanced Security Integration")
        print()
        
        # Step 1: Setup
        if not self.step1_setup_vault():
            print("\n❌ Test suite failed at Step 1")
            return
        
        # Step 2: Test without NFC
        if not self.step2_test_without_nfc():
            print("\n❌ Test suite failed at Step 2")
            return
        
        # Step 3: Test with NFC
        if not self.step3_test_with_nfc():
            print("\n❌ Test suite failed at Step 3")
            return
        
        # Success summary
        print("\n" + "🏆" * 60)
        print("✅ ALL TESTS PASSED - NFC AUTHENTICATION WORKING")
        print("🏆" * 60)
        print()
        print("🔐 Step 1: ✅ NFC vault creation successful")
        print("🚫 Step 2: ✅ Access denied without NFC tag")
        print("🔓 Step 3: ✅ Access granted with correct NFC tag")
        print()
        print("🚀 System ready for Google Cloud integration!")

def main():
    auth = GoogleCloudNFCAuth()
    
    if len(sys.argv) > 1:
        step = sys.argv[1]
        if step == "1":
            auth.step1_setup_vault()
        elif step == "2":
            auth.step2_test_without_nfc()
        elif step == "3":
            auth.step3_test_with_nfc()
        else:
            print("Usage: python3 gcp_nfc_integration_test.py [1|2|3]")
    else:
        auth.run_complete_test()

if __name__ == "__main__":
    main()
