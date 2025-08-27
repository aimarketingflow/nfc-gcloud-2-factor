#!/usr/bin/env python3
"""
Mock NFC Authentication Test
Uses confirmed working UID (0054071282) to test cloud authentication flow
Bypasses pyscard reader detection issues

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import sys
import os
sys.path.append('..')

import json
import requests
from datetime import datetime

def mock_nfc_scan(tag_name: str) -> bytes:
    """Mock NFC scan using confirmed working UID"""
    
    # Your confirmed working UID: 0054071282
    confirmed_uid = "0054071282"
    
    print(f"📱 Mock scanning {tag_name}...")
    print(f"   Using confirmed UID: {confirmed_uid}")
    
    # Convert hex string to bytes
    uid_bytes = bytes.fromhex(confirmed_uid)
    
    print(f"✅ {tag_name} scanned successfully")
    print(f"   Bytes: {uid_bytes}")
    print(f"   Hex: {uid_bytes.hex().upper()}")
    
    return uid_bytes

def test_cloud_registration_flow():
    """Test complete cloud registration with mock NFC data"""
    
    print("🔐 Testing Cloud Registration with Mock NFC Data")
    print("=" * 50)
    print()
    
    # Mock dual NFC registration
    print("🔑 Reading PRIMARY NFC token...")
    primary_nfc = mock_nfc_scan("PRIMARY NFC tag")
    
    print("🔑 Reading SECONDARY NFC token...")
    # For dual token test, use slightly modified UID
    secondary_uid = "0054071283" # Last digit changed for testing
    secondary_nfc = bytes.fromhex(secondary_uid)
    print(f"📱 Mock scanning SECONDARY NFC tag...")
    print(f"   Using test UID: {secondary_uid}")
    print(f"✅ SECONDARY NFC tag scanned successfully")
    
    # Test user ID
    test_user_id = "aimf_test_user_androidapp"
    
    # Prepare registration data
    registration_data = {
        "user_id": test_user_id,
        "primary_nfc_hash": primary_nfc.hex(),
        "secondary_nfc_hash": secondary_nfc.hex(),
        "metadata": {
            "device_type": "macOS",
            "registration_time": datetime.now().isoformat(),
            "client_version": "1.0.0",
            "test_mode": True,
            "hardware_confirmed": True
        }
    }
    
    print(f"\n📋 Registration Data:")
    print(f"   User ID: {test_user_id}")
    print(f"   Primary hash: {primary_nfc.hex()}")
    print(f"   Secondary hash: {secondary_nfc.hex()}")
    
    # Try to register with local AIMF auth server
    try:
        auth_server_url = "http://localhost:5003"
        print(f"\n🌐 Connecting to AIMF Auth Server: {auth_server_url}")
        
        response = requests.post(
            f"{auth_server_url}/v1/register",
            json=registration_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"🎉 Registration successful!")
            print(f"   Token Fingerprint: {result.get('token_fingerprint', 'N/A')[:16]}...")
            
            # Save test config
            config = {
                "user_id": test_user_id,
                "token_fingerprint": result.get('token_fingerprint'),
                "registered_at": datetime.now().isoformat(),
                "test_mode": True,
                "primary_uid": primary_nfc.hex(),
                "secondary_uid": secondary_nfc.hex()
            }
            
            with open('mock_test_config.json', 'w') as f:
                json.dump(config, f, indent=2)
            
            return True
            
        else:
            print(f"❌ Registration failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to AIMF Auth Server")
        print("   Start server: python3 ../aimf_auth_server.py")
        return False
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return False

def test_cloud_authentication_flow():
    """Test cloud authentication with mock NFC data"""
    
    print("\n🔒 Testing Cloud Authentication Flow")
    print("=" * 40)
    
    # Use same mock UIDs
    primary_nfc = bytes.fromhex("0054071282")
    secondary_nfc = bytes.fromhex("0054071283")
    
    auth_data = {
        "primary_nfc_hash": primary_nfc.hex(),
        "secondary_nfc_hash": secondary_nfc.hex()
    }
    
    try:
        auth_server_url = "http://localhost:5003"
        response = requests.post(
            f"{auth_server_url}/v1/authenticate",
            json=auth_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print("🎉 Authentication successful!")
            print(f"   User ID: {result.get('user_id')}")
            print(f"   Session Token: {result.get('session_token', '')[:16]}...")
            print(f"   Expires: {result.get('expires_at', '')[:19]}")
            return result.get('session_token')
        else:
            print(f"❌ Authentication failed: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return None

if __name__ == "__main__":
    print("🔷 AIMF Mock NFC Cloud Authentication Test")
    print("   Using confirmed working UID: 0054071282")
    print()
    
    # Test registration
    reg_success = test_cloud_registration_flow()
    
    if reg_success:
        # Test authentication
        session_token = test_cloud_authentication_flow()
        
        if session_token:
            print("\n✅ Complete Flow Test PASSED!")
            print("   Mock NFC → Cloud Registration → Authentication ✅")
            print("\nNext: Test with real Google Cloud integration")
        else:
            print("\n❌ Authentication test failed")
    else:
        print("\n❌ Registration test failed")
        print("Check AIMF auth server is running")
