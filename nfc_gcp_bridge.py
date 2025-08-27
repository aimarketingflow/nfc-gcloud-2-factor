#!/usr/bin/env python3
"""
NFC Google Cloud Authentication Bridge
Connects NFC Chaos Writer system with Google Cloud Platform services

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import os
import sys
import json
import hashlib
import pickle
from typing import Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

try:
    from smartcard.System import readers
    from smartcard.util import toHexString
except ImportError:
    print("❌ pyscard not available - NFC functionality disabled")
    readers = None

try:
    from google.auth.transport.requests import Request
    from google.auth import credentials
    from google.oauth2 import service_account
    from google.cloud import iam_credentials_v1
    from google.cloud import storage
    from google.cloud import compute_v1
    import googleapiclient.discovery
except ImportError:
    print("❌ Google Cloud libraries not available")
    sys.exit(1)

@dataclass
class NFCCloudSession:
    """Represents an authenticated NFC-to-Cloud session"""
    nfc_fingerprint: str
    project_id: str
    service_account_email: str
    access_token: str
    expires_at: datetime
    permissions_level: int

class NFCGCPBridge:
    """Bridge service connecting NFC authentication to Google Cloud Platform"""
    
    def __init__(self):
        self.vault_file = "../.chaos_vault"
        self.config_file = "nfc_gcp_config.json"
        self.sessions = {}
        self.chaos_vault = self._load_chaos_vault()
        self.gcp_config = self._load_gcp_config()
        
    def _load_chaos_vault(self) -> Dict:
        """Load NFC chaos value vault"""
        try:
            if os.path.exists(self.vault_file):
                with open(self.vault_file, 'rb') as f:
                    return pickle.load(f)
            else:
                print(f"⚠️  Chaos vault not found at {self.vault_file}")
                return {"chaos_values": [], "generated_count": 0}
        except Exception as e:
            print(f"❌ Error loading chaos vault: {e}")
            return {"chaos_values": [], "generated_count": 0}
    
    def _load_gcp_config(self) -> Dict:
        """Load Google Cloud configuration"""
        default_config = {
            "project_id": "",
            "service_account_key_path": "",
            "default_permissions": {
                1: "roles/viewer",
                2: "roles/editor", 
                3: "roles/owner"
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    return {**default_config, **config}
            else:
                print(f"📝 Creating default config at {self.config_file}")
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                return default_config
        except Exception as e:
            print(f"❌ Error loading GCP config: {e}")
            return default_config
    
    def verify_nfc_token(self, nfc_data: bytes) -> Optional[str]:
        """Verify NFC token against chaos vault"""
        if not self.chaos_vault.get("chaos_values"):
            print("❌ No chaos values in vault")
            return None
            
        # Create fingerprint from NFC data
        fingerprint = hashlib.sha256(nfc_data).hexdigest()[:16]
        
        # Check if this chaos value exists in vault
        for stored_value in self.chaos_vault["chaos_values"]:
            if stored_value == nfc_data:
                print(f"✅ NFC token verified - fingerprint: {fingerprint}")
                return fingerprint
        
        print("❌ NFC token verification failed")
        return None
    
    def authenticate_to_gcp(self, nfc_fingerprint: str, permission_level: int = 1) -> Optional[NFCCloudSession]:
        """Authenticate to Google Cloud using NFC-verified credentials"""
        if not self.gcp_config.get("project_id") or not self.gcp_config.get("service_account_key_path"):
            print("❌ GCP configuration incomplete")
            return None
            
        try:
            # Load service account credentials
            credentials_obj = service_account.Credentials.from_service_account_file(
                self.gcp_config["service_account_key_path"]
            )
            
            # Create session with NFC binding
            session = NFCCloudSession(
                nfc_fingerprint=nfc_fingerprint,
                project_id=self.gcp_config["project_id"],
                service_account_email=credentials_obj.service_account_email,
                access_token=credentials_obj.token,
                expires_at=datetime.now() + timedelta(hours=1),
                permissions_level=permission_level
            )
            
            # Store session
            self.sessions[nfc_fingerprint] = session
            
            print(f"✅ GCP authentication successful")
            print(f"   Project: {session.project_id}")
            print(f"   Service Account: {session.service_account_email}")
            print(f"   Permission Level: {permission_level}")
            
            return session
            
        except Exception as e:
            print(f"❌ GCP authentication failed: {e}")
            return None
    
    def test_gcp_access(self, session: NFCCloudSession) -> bool:
        """Test Google Cloud access with authenticated session"""
        try:
            # Test Storage access
            storage_client = storage.Client(project=session.project_id)
            buckets = list(storage_client.list_buckets())
            print(f"📦 Storage access: {len(buckets)} buckets accessible")
            
            # Test Compute access (list instances)
            compute_client = compute_v1.InstancesClient()
            # Note: This would need proper zone configuration
            print("💻 Compute access: Client initialized successfully")
            
            return True
            
        except Exception as e:
            print(f"❌ GCP access test failed: {e}")
            return False
    
    def read_nfc_tag(self) -> Optional[bytes]:
        """Read NFC tag using PC/SC interface"""
        if not readers:
            print("❌ NFC readers not available")
            return None
            
        try:
            reader_list = readers()
            if not reader_list:
                print("❌ No NFC readers found")
                return None
                
            print(f"📱 Found {len(reader_list)} NFC reader(s)")
            reader = reader_list[0]
            
            print(f"🔍 Using reader: {reader}")
            print("   Please place NFC tag on reader...")
            
            connection = reader.createConnection()
            connection.connect()
            
            # Get card UID
            response, sw1, sw2 = connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            
            if sw1 == 0x90 and sw2 == 0x00:
                uid_data = bytes(response)
                print(f"✅ NFC tag read successfully")
                print(f"   UID: {toHexString(response)}")
                return uid_data
            else:
                print(f"❌ Failed to read NFC tag: {sw1:02X} {sw2:02X}")
                return None
                
        except Exception as e:
            print(f"❌ NFC reading error: {e}")
            return None
    
    def authenticate_workflow(self) -> Optional[NFCCloudSession]:
        """Complete NFC-to-GCP authentication workflow"""
        print("🔐 Starting NFC-to-Google Cloud authentication...")
        
        # Step 1: Read NFC tag
        nfc_data = self.read_nfc_tag()
        if not nfc_data:
            return None
        
        # Step 2: Verify against chaos vault
        fingerprint = self.verify_nfc_token(nfc_data)
        if not fingerprint:
            return None
        
        # Step 3: Authenticate to GCP
        session = self.authenticate_to_gcp(fingerprint)
        if not session:
            return None
        
        # Step 4: Test access
        if self.test_gcp_access(session):
            print("🎉 NFC-to-GCP authentication complete!")
            return session
        else:
            return None

def main():
    """Main application entry point"""
    print("🔷 NFC Google Cloud Authentication Bridge")
    print("   AIMF LLC - MobileShield NFC Chaos Writer")
    print()
    
    bridge = NFCGCPBridge()
    
    # Display current configuration
    print("📋 Current Configuration:")
    print(f"   Project ID: {bridge.gcp_config.get('project_id', 'Not set')}")
    print(f"   Service Account: {bridge.gcp_config.get('service_account_key_path', 'Not set')}")
    print(f"   Chaos Vault: {len(bridge.chaos_vault.get('chaos_values', []))} values")
    print()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "config":
            print("📝 Configuration Setup:")
            project_id = input("Enter GCP Project ID: ").strip()
            sa_path = input("Enter Service Account Key Path: ").strip()
            
            bridge.gcp_config["project_id"] = project_id
            bridge.gcp_config["service_account_key_path"] = sa_path
            
            with open(bridge.config_file, 'w') as f:
                json.dump(bridge.gcp_config, f, indent=2)
            
            print("✅ Configuration saved!")
            
        elif command == "test":
            print("🧪 Testing NFC-to-GCP authentication...")
            session = bridge.authenticate_workflow()
            if session:
                print("\n✅ Test completed successfully!")
            else:
                print("\n❌ Test failed!")
                
        elif command == "vault":
            print(f"🗄️  Chaos Vault Status:")
            print(f"   Values: {len(bridge.chaos_vault.get('chaos_values', []))}")
            print(f"   Generated: {bridge.chaos_vault.get('generated_count', 0)}")
    else:
        print("Usage:")
        print("  python3 nfc_gcp_bridge.py config   - Configure GCP settings")
        print("  python3 nfc_gcp_bridge.py test     - Test NFC-to-GCP authentication")
        print("  python3 nfc_gcp_bridge.py vault    - Show chaos vault status")

if __name__ == "__main__":
    main()
