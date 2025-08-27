
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
