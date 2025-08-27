#!/usr/bin/env python3
"""
Test Setup for AIMF NFC Cloud Authentication
Uses your-gcp-project-id Google Cloud project

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import os
import json
import subprocess
from pathlib import Path

def setup_testing_environment():
    """Set up testing environment for your-gcp-project-id project"""
    
    print("🔷 AIMF NFC Cloud Authentication Test Setup")
    print("   Project: your-gcp-project-id")
    print()
    
    # Create test directory
    test_dir = Path("test_deployment")
    test_dir.mkdir(exist_ok=True)
    
    print("✅ Test directory created")
    
    # Project configuration
    project_config = {
        "project_id": "your-gcp-project-id",
        "service_account_email": "firebase-adminsdk@your-gcp-project-id.iam.gserviceaccount.com",
        "service_account_id": "117185563659756571309",
        "auth_server_url": "http://localhost:5000",  # Local testing first
        "test_user_id": "aimf_test_user"
    }
    
    with open(test_dir / "project_config.json", 'w') as f:
        json.dump(project_config, f, indent=2)
    
    print("✅ Project configuration saved")
    
    # Create service account key instructions
    instructions = """
# Service Account Key Setup Instructions

## Step 1: Download Service Account Key
1. Go to: https://console.cloud.google.com/iam-admin/serviceaccounts?project=your-gcp-project-id
2. Find: firebase-adminsdk@your-gcp-project-id.iam.gserviceaccount.com
3. Click "..." → "Manage Keys" → "Add Key" → "Create New Key"
4. Choose JSON format and download
5. Save as: service_account_key.json in this directory

## Step 2: Test Components
Run tests in this order:

```bash
# 1. Test service account locally
python3 test_service_account.py

# 2. Start AIMF auth server (in separate terminal)
python3 ../aimf_auth_server.py

# 3. Test NFC registration 
python3 test_nfc_registration.py

# 4. Test complete authentication flow
python3 test_complete_flow.py
```

## Step 3: Deploy to Cloud (later)
- Deploy aimf_auth_server.py to Google Cloud Run
- Configure domain: auth.aimf.ai
- Update client configs to use production URL
"""
    
    with open(test_dir / "SETUP_INSTRUCTIONS.md", 'w') as f:
        f.write(instructions)
    
    print("✅ Setup instructions created")
    print()
    print("📁 Test files created in: test_deployment/")
    print("📋 Next: Follow SETUP_INSTRUCTIONS.md")

if __name__ == "__main__":
    setup_testing_environment()
