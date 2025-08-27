#!/usr/bin/env python3
"""
Test NFC Token Registration with AIMF Auth Server
Register dual NFC tokens for androidappmobileshield project testing

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import sys
import os
sys.path.append('..')

# Import our cloud auth client
from cloud_auth_client import CloudNFCAuthenticator

def test_nfc_registration():
    """Test NFC token registration with local auth server"""
    
    print("🔐 Testing NFC Token Registration")
    print("   AIMF Auth Server: http://localhost:5000")
    print()
    
    # Initialize authenticator with local server
    authenticator = CloudNFCAuthenticator("http://localhost:5000")
    
    # Test user ID
    test_user_id = "aimf_test_user_androidapp"
    
    print(f"📋 Registering user: {test_user_id}")
    print("   This will require scanning TWO NFC tags")
    print()
    
    # Attempt registration
    success = authenticator.register_with_cloud(test_user_id)
    
    if success:
        print("\n🎉 NFC Registration Test Passed!")
        print("✅ Dual NFC tokens registered with AIMF server")
        print("✅ User config saved locally")
        print("\nNext: Test authentication flow")
        print("Run: python3 test_complete_flow.py")
        return True
    else:
        print("\n❌ NFC Registration Test Failed")
        print("Check:")
        print("- AIMF auth server is running (python3 ../aimf_auth_server.py)")
        print("- NFC reader is connected")
        print("- NFC tags are available")
        return False

if __name__ == "__main__":
    print("⚠️  Prerequisites:")
    print("1. AIMF auth server running: python3 ../aimf_auth_server.py")
    print("2. NFC reader connected")
    print("3. Two NFC tags ready")
    print()
    
    input("Press Enter when ready to start registration...")
    
    success = test_nfc_registration()
    exit(0 if success else 1)
