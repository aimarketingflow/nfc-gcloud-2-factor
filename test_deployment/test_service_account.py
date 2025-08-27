#!/usr/bin/env python3
"""
Test Google Cloud Service Account Access
Tests your-gcp-project-id project connectivity

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import os
import json
from pathlib import Path

def test_service_account():
    """Test service account authentication and permissions"""
    
    print("🔍 Testing Google Cloud Service Account")
    print("   Project: your-gcp-project-id")
    print()
    
    # Check for service account key
    sa_key_file = Path("service_account_key.json")
    if not sa_key_file.exists():
        print("❌ Service account key file not found!")
        print("   Please download from Google Cloud Console:")
        print("   https://console.cloud.google.com/iam-admin/serviceaccounts?project=your-gcp-project-id")
        print("   Save as: service_account_key.json")
        return False
    
    try:
        # Load and validate service account key
        with open(sa_key_file, 'r') as f:
            sa_data = json.load(f)
        
        print("✅ Service account key loaded")
        print(f"   Type: {sa_data.get('type')}")
        print(f"   Project ID: {sa_data.get('project_id')}")
        print(f"   Client Email: {sa_data.get('client_email')}")
        print()
        
        # Verify it's the expected service account
        expected_email = "firebase-adminsdk-fbsyc@your-gcp-project-id.iam.gserviceaccount.com"
        if sa_data.get('client_email') != expected_email:
            print(f"⚠️  Unexpected service account email: {sa_data.get('client_email')}")
            print(f"   Expected: {expected_email}")
        
        # Test Google Cloud SDK installation
        import subprocess
        try:
            result = subprocess.run(['gcloud', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✅ Google Cloud SDK installed")
                gcloud_version = result.stdout.split('\n')[0]
                print(f"   {gcloud_version}")
            else:
                print("❌ Google Cloud SDK not working")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("❌ Google Cloud SDK not installed")
            print("   Install: https://cloud.google.com/sdk/docs/install")
            return False
        
        # Test authentication with service account
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = str(sa_key_file.absolute())
        
        try:
            from google.cloud import storage
            from google.auth import default
            
            # Get default credentials
            credentials, project = default()
            print(f"✅ Authentication successful")
            print(f"   Project: {project}")
            
            # Test API access
            client = storage.Client()
            buckets = list(client.list_buckets())
            print(f"✅ Storage API access confirmed")
            print(f"   Found {len(buckets)} storage buckets")
            
            return True
            
        except Exception as e:
            print(f"❌ Google Cloud API test failed: {e}")
            print("   Check service account permissions")
            return False
            
    except Exception as e:
        print(f"❌ Service account test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_service_account()
    if success:
        print("\n🎉 Service account test passed!")
        print("   Ready for NFC authentication testing")
    else:
        print("\n❌ Service account test failed")
        print("   Fix issues before proceeding")
        exit(1)
