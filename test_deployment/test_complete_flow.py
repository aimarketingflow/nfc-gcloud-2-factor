#!/usr/bin/env python3
"""
Test Complete NFC Cloud Authentication Flow
Tests full integration: NFC → AIMF Cloud → Google Cloud
Uses your-gcp-project-id project with API key

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import sys
import os
import json
import subprocess
sys.path.append('..')

from cloud_auth_client import CloudNFCAuthenticator

def load_test_config():
    """Load test configuration"""
    with open('test_config.json', 'r') as f:
        return json.load(f)

def test_google_cloud_api_access(config):
    """Test direct Google Cloud API access using API key"""
    
    print("🔧 Testing Google Cloud API Access")
    
    try:
        import requests
        
        # Test Storage API
        storage_url = f"https://storage.googleapis.com/storage/v1/b?project={config['project_id']}&key={config['api_key']}"
        
        response = requests.get(storage_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            bucket_count = len(data.get('items', []))
            print(f"✅ Storage API access successful")
            print(f"   Found {bucket_count} storage buckets")
            return True
        else:
            print(f"❌ Storage API failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ API test failed: {e}")
        return False

def test_complete_authentication_flow():
    """Test complete authentication flow with Google Cloud access"""
    
    print("🌐 Testing Complete NFC Cloud Authentication Flow")
    print("   Local NFC → AIMF Server → Google Cloud Access")
    print()
    
    # Load configuration
    config = load_test_config()
    print(f"📋 Project: {config['project_id']}")
    print(f"🔑 API Key: {config['api_key'][:20]}...")
    print()
    
    # Initialize authenticator
    authenticator = CloudNFCAuthenticator(config['auth_server_url'])
    
    print("Phase 1: Test Direct Google Cloud API Access")
    api_success = test_google_cloud_api_access(config)
    if not api_success:
        print("❌ Direct API access failed - check API key and permissions")
        return False
    print()
    
    print("Phase 2: Cloud Authentication with AIMF Server")
    print("   Authenticating with AIMF server using dual NFC...")
    
    # Authenticate with cloud service
    session_token = authenticator.authenticate_with_cloud()
    
    if not session_token:
        print("❌ Cloud authentication failed")
        print("   Make sure:")
        print("   - AIMF auth server is running (python3 ../aimf_auth_server.py)")
        print("   - NFC tokens are registered (python3 test_nfc_registration.py)")
        return False
    
    print("✅ Cloud authentication successful!")
    print(f"   Session token: {session_token[:32]}...")
    print()
    
    print("Phase 3: Session Validation")
    if authenticator.validate_session():
        print("✅ Session validation passed")
    else:
        print("❌ Session validation failed")
        return False
    
    print()
    print("Phase 4: Google Cloud Access Request")
    if authenticator.request_gcloud_access():
        print("✅ Google Cloud access authorized!")
    else:
        print("❌ Google Cloud access denied")
        return False
    
    print()
    print("Phase 5: Test Integrated Google Cloud Operations")
    
    # Test gcloud CLI if available
    try:
        result = subprocess.run(['gcloud', 'projects', 'describe', config['project_id']], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✅ gcloud CLI access working")
            project_info = result.stdout
            print(f"   Project validated via gcloud")
        else:
            print("⚠️  gcloud CLI not configured or project access limited")
            
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("⚠️  gcloud CLI not available")
    
    print()
    print("Phase 6: Firebase API Test")
    
    try:
        import requests
        
        # Test Firebase project info
        firebase_url = f"https://firebase.googleapis.com/v1beta1/projects/{config['project_id']}?key={config['api_key']}"
        
        response = requests.get(firebase_url, timeout=10)
        
        if response.status_code == 200:
            project_data = response.json()
            print("✅ Firebase API access successful")
            print(f"   Project Name: {project_data.get('displayName', 'N/A')}")
            print(f"   Project Number: {project_data.get('projectNumber', 'N/A')}")
        else:
            print(f"⚠️  Firebase API limited: {response.status_code}")
            
    except Exception as e:
        print(f"⚠️  Firebase API test failed: {e}")
    
    return True

def main():
    """Main test execution"""
    
    print("🔷 AIMF NFC Cloud Authentication - Complete Flow Test")
    print("   your-gcp-project-id Project Integration")
    print()
    
    # Check prerequisites
    print("📋 Checking Prerequisites...")
    
    if not os.path.exists('test_config.json'):
        print("❌ test_config.json not found")
        exit(1)
    
    config = load_test_config()
    
    print("✅ Test configuration loaded")
    print(f"   Project: {config['project_id']}")
    print(f"   Auth Server: {config['auth_server_url']}")
    print()
    
    print("⚠️  Prerequisites for this test:")
    print("1. AIMF auth server running: python3 ../aimf_auth_server.py")
    print("2. NFC tokens registered: python3 test_nfc_registration.py")
    print("3. NFC reader connected")
    print("4. Two NFC tags ready")
    print()
    
    input("Press Enter when ready to start complete flow test...")
    print()
    
    success = test_complete_authentication_flow()
    
    if success:
        print("\n🎉 Complete Authentication Flow Test PASSED!")
        print("✅ NFC → AIMF Cloud → Google Cloud integration working")
        print("✅ API access confirmed")
        print("✅ Session management functional")
        print("\nNext: Deploy AIMF auth server to production")
    else:
        print("\n❌ Complete Authentication Flow Test FAILED")
        print("Check error messages above and fix issues")
        exit(1)

if __name__ == "__main__":
    main()
