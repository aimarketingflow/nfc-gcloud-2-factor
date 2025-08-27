#!/usr/bin/env python3
"""
Cloud Authentication Client - Integrates with AIMF Auth Server
Enhanced dual NFC authentication with cloud verification

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import os
import json
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
except ImportError:
    print("❌ pyscard not available - install with: pip install pyscard")
    exit(1)

class CloudNFCAuthenticator:
    """Enhanced NFC authentication with cloud verification"""
    
    def __init__(self, auth_server_url: str = "https://auth.aimf.ai"):
        self.auth_server_url = auth_server_url.rstrip('/')
        self.api_version = "v1"
        self.session_token = None
        
        # Local paths
        self.config_dir = Path.home() / ".aimf_auth"
        self.config_dir.mkdir(exist_ok=True)
        self.session_file = self.config_dir / "session.json"
        self.user_config = self.config_dir / "config.json"
        
    def read_nfc_tag(self, tag_name: str) -> Optional[bytes]:
        """Read NFC tag and return raw data"""
        if not readers:
            print("❌ No NFC readers available")
            return None
        
        try:
            reader_list = readers()
            if not reader_list:
                print("❌ No NFC readers detected")
                return None
            
            reader = reader_list[0]
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
                print(f"❌ Failed to read {tag_name}")
                return None
                
        except Exception as e:
            print(f"❌ NFC error: {e}")
            return None
    
    def register_with_cloud(self, user_id: str) -> bool:
        """Register dual NFC tokens with AIMF cloud service"""
        
        print("🔐 Registering NFC token pair with AIMF Auth Server...")
        print()
        
        # Read dual NFC tokens
        primary_nfc = self.read_nfc_tag("PRIMARY NFC tag")
        if not primary_nfc:
            return False
        
        secondary_nfc = self.read_nfc_tag("SECONDARY NFC tag")
        if not secondary_nfc:
            return False
        
        # Prepare registration data
        registration_data = {
            "user_id": user_id,
            "primary_nfc_hash": primary_nfc.hex(),
            "secondary_nfc_hash": secondary_nfc.hex(),
            "metadata": {
                "device_type": "macOS",
                "registration_time": datetime.now().isoformat(),
                "client_version": "1.0.0"
            }
        }
        
        try:
            response = requests.post(
                f"{self.auth_server_url}/{self.api_version}/register",
                json=registration_data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Registration successful!")
                print(f"   Token Fingerprint: {result['token_fingerprint'][:16]}...")
                
                # Save user config
                config = {
                    "user_id": user_id,
                    "token_fingerprint": result['token_fingerprint'],
                    "registered_at": datetime.now().isoformat()
                }
                
                with open(self.user_config, 'w') as f:
                    json.dump(config, f, indent=2)
                
                return True
            else:
                print(f"❌ Registration failed: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Cloud registration error: {e}")
            return False
    
    def authenticate_with_cloud(self) -> Optional[str]:
        """Authenticate with cloud using dual NFC tokens"""
        
        print("🌐 Authenticating with AIMF Cloud Service...")
        print()
        
        # Read dual NFC tokens
        primary_nfc = self.read_nfc_tag("PRIMARY NFC tag")
        if not primary_nfc:
            return None
        
        secondary_nfc = self.read_nfc_tag("SECONDARY NFC tag")
        if not secondary_nfc:
            return None
        
        # Prepare authentication data
        auth_data = {
            "primary_nfc_hash": primary_nfc.hex(),
            "secondary_nfc_hash": secondary_nfc.hex()
        }
        
        try:
            response = requests.post(
                f"{self.auth_server_url}/{self.api_version}/authenticate",
                json=auth_data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Save session token
                session_data = {
                    "session_token": result["session_token"],
                    "user_id": result["user_id"],
                    "expires_at": result["expires_at"],
                    "permissions": result["permissions"],
                    "authenticated_at": datetime.now().isoformat()
                }
                
                with open(self.session_file, 'w') as f:
                    json.dump(session_data, f, indent=2)
                
                self.session_token = result["session_token"]
                
                print("🎉 Cloud authentication successful!")
                print(f"   User ID: {result['user_id']}")
                print(f"   Valid until: {result['expires_at'][:19]}")
                print(f"   Permissions: {', '.join(result['permissions'])}")
                
                return result["session_token"]
            else:
                print(f"❌ Authentication failed: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Cloud authentication error: {e}")
            return None
    
    def validate_session(self) -> bool:
        """Validate current session with cloud"""
        
        if not self.session_token:
            if self.session_file.exists():
                with open(self.session_file, 'r') as f:
                    session_data = json.load(f)
                    self.session_token = session_data.get("session_token")
        
        if not self.session_token:
            return False
        
        try:
            headers = {"Authorization": f"Bearer {self.session_token}"}
            response = requests.post(
                f"{self.auth_server_url}/{self.api_version}/validate",
                headers=headers,
                timeout=5
            )
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    def request_gcloud_access(self) -> bool:
        """Request Google Cloud access through cloud service"""
        
        if not self.session_token:
            print("❌ No valid session token")
            return False
        
        try:
            headers = {"Authorization": f"Bearer {self.session_token}"}
            response = requests.post(
                f"{self.auth_server_url}/{self.api_version}/gcloud/access",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Google Cloud access authorized by AIMF server")
                print(f"   Valid until: {result['valid_until'][:19]}")
                return True
            else:
                print(f"❌ Access denied: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Access request error: {e}")
            return False
    
    def setup_gcloud_with_cloud_auth(self) -> bool:
        """Complete gcloud setup with cloud authentication"""
        
        # Check existing session
        if self.validate_session():
            print("🔍 Valid session found - requesting cloud access...")
            if self.request_gcloud_access():
                print("✅ Google Cloud authentication complete!")
                return True
        
        # Need fresh authentication
        token = self.authenticate_with_cloud()
        if token:
            if self.request_gcloud_access():
                print("✅ Google Cloud authentication complete!")
                return True
        
        return False

def main():
    """Main CLI interface"""
    import sys
    
    print("🔷 AIMF Cloud NFC Authentication")
    print("   Enhanced security with cloud verification")
    print()
    
    # Configuration
    auth_server_url = os.environ.get('AIMF_AUTH_URL', 'https://auth.aimf.ai')
    authenticator = CloudNFCAuthenticator(auth_server_url)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--register":
            if len(sys.argv) < 3:
                print("Usage: python3 cloud_auth_client.py --register <user_id>")
                exit(1)
            
            user_id = sys.argv[2]
            success = authenticator.register_with_cloud(user_id)
            
            if success:
                print("✅ Registration complete!")
                print("   Use 'python3 cloud_auth_client.py' to authenticate")
            else:
                exit(1)
                
        elif sys.argv[1] == "--validate":
            if authenticator.validate_session():
                print("✅ Session is valid")
            else:
                print("❌ Session invalid or expired")
                exit(1)
                
        else:
            print("Usage:")
            print("  python3 cloud_auth_client.py                  - Authenticate with cloud")
            print("  python3 cloud_auth_client.py --register <id>  - Register NFC tokens")
            print("  python3 cloud_auth_client.py --validate       - Validate session")
    
    else:
        # Standard authentication
        success = authenticator.setup_gcloud_with_cloud_auth()
        if not success:
            print("❌ Cloud authentication failed")
            exit(1)

if __name__ == "__main__":
    main()
