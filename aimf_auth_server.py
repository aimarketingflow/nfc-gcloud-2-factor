#!/usr/bin/env python3
"""
AIMF Authentication Server - Cloud-hosted NFC token verification
Provides remote validation for NFC Chaos Writer ecosystem

Deploy this on Google Cloud Run or AWS Lambda
AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import os
import json
import hashlib
import hmac
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from functools import wraps

try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    import redis
    import jwt
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
except ImportError:
    print("❌ Dependencies missing - install with:")
    print("pip install flask flask-cors redis pyjwt cryptography")
    exit(1)

app = Flask(__name__)
CORS(app)

# Configuration
JWT_SECRET = os.environ.get('AIMF_JWT_SECRET', 'dev-secret-change-in-production')
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
API_VERSION = "v1"

# Redis connection for session storage and rate limiting
try:
    redis_client = redis.from_url(REDIS_URL)
except Exception as e:
    print(f"⚠️  Redis not available: {e}")
    redis_client = None

class AIMFAuthServer:
    """AIMF NFC token verification and session management"""
    
    def __init__(self):
        self.registered_tokens = {}  # In production: use secure database
        self.session_cache = {}      # In production: use Redis
        self.audit_log = []         # In production: use cloud logging
        
    def register_nfc_token_pair(self, user_id: str, primary_nfc: bytes, 
                               secondary_nfc: bytes, metadata: dict) -> str:
        """Register a dual NFC token pair for a user"""
        
        # Create combined fingerprint
        combined_data = primary_nfc + secondary_nfc + b"aimf_auth_2024"
        token_fingerprint = hashlib.sha256(combined_data).hexdigest()
        
        # Store registration
        registration = {
            "user_id": user_id,
            "token_fingerprint": token_fingerprint,
            "registered_at": datetime.now().isoformat(),
            "metadata": metadata,
            "active": True,
            "last_used": None,
            "use_count": 0
        }
        
        self.registered_tokens[token_fingerprint] = registration
        
        # Audit log
        self.log_event("token_registered", {
            "user_id": user_id,
            "token_fingerprint": token_fingerprint[:16],
            "metadata": metadata
        })
        
        return token_fingerprint
    
    def verify_nfc_token_pair(self, primary_nfc: bytes, secondary_nfc: bytes,
                             client_info: dict) -> Optional[dict]:
        """Verify dual NFC token pair against registered tokens"""
        
        # Create fingerprint to check
        combined_data = primary_nfc + secondary_nfc + b"aimf_auth_2024"
        check_fingerprint = hashlib.sha256(combined_data).hexdigest()
        
        # Look up registration
        registration = self.registered_tokens.get(check_fingerprint)
        
        if not registration or not registration["active"]:
            self.log_event("auth_failed", {
                "reason": "token_not_found",
                "fingerprint": check_fingerprint[:16],
                "client_info": client_info
            })
            return None
        
        # Rate limiting check
        if self.check_rate_limit(registration["user_id"], client_info):
            self.log_event("auth_failed", {
                "reason": "rate_limited",
                "user_id": registration["user_id"],
                "client_info": client_info
            })
            return None
        
        # Update usage stats
        registration["last_used"] = datetime.now().isoformat()
        registration["use_count"] += 1
        
        # Generate session token
        session_token = self.create_session_token(registration, client_info)
        
        self.log_event("auth_success", {
            "user_id": registration["user_id"],
            "session_token": session_token[:16],
            "client_info": client_info
        })
        
        return {
            "session_token": session_token,
            "user_id": registration["user_id"],
            "expires_at": (datetime.now() + timedelta(hours=8)).isoformat(),
            "permissions": ["gcloud_access", "storage_read", "compute_read"]
        }
    
    def create_session_token(self, registration: dict, client_info: dict) -> str:
        """Create JWT session token with enhanced device binding"""
        
        payload = {
            "user_id": registration["user_id"],
            "token_fingerprint": registration["token_fingerprint"][:16],
            "issued_at": time.time(),
            "expires_at": time.time() + (8 * 3600),  # 8 hours
            "client_fingerprint": hashlib.sha256(
                json.dumps(client_info, sort_keys=True).encode()
            ).hexdigest()[:16],
            "ip_address": client_info.get("ip_address"),  # Store originating IP
            "permissions": ["gcloud_access", "storage_read", "compute_read"]
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        
        # Cache session info
        self.session_cache[token] = {
            "payload": payload,
            "active": True,
            "created_at": datetime.now().isoformat()
        }
        
        return token
    
    def validate_session_token(self, token: str, client_info: dict, required_permissions: List[str] = None) -> Optional[dict]:
        """Validate session token with strict device binding and check permissions"""
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            
            # Check expiration
            if time.time() > payload["expires_at"]:
                self.log_event("session_expired", {"token": token[:16], "client_info": client_info})
                return None
            
            # STRICT DEVICE BINDING: Verify client fingerprint matches
            current_fingerprint = hashlib.sha256(
                json.dumps(client_info, sort_keys=True).encode()
            ).hexdigest()[:16]
            
            if payload.get("client_fingerprint") != current_fingerprint:
                self.log_event("device_mismatch", {
                    "expected_fingerprint": payload.get("client_fingerprint"),
                    "actual_fingerprint": current_fingerprint,
                    "client_info": client_info,
                    "token": token[:16]
                })
                return None
            
            # STRICT IP BINDING: Verify IP hasn't changed significantly
            token_ip = payload.get("ip_address")
            current_ip = client_info.get("ip_address")
            if token_ip and current_ip and token_ip != current_ip:
                # Allow same /24 subnet for dynamic IPs but log suspicious changes
                if not self._is_ip_in_same_subnet(token_ip, current_ip):
                    self.log_event("ip_change_suspicious", {
                        "token_ip": token_ip,
                        "current_ip": current_ip,
                        "client_info": client_info,
                        "token": token[:16]
                    })
                    return None
            
            # Check cached session
            session_info = self.session_cache.get(token)
            if not session_info or not session_info["active"]:
                self.log_event("session_invalid", {"token": token[:16], "client_info": client_info})
                return None
            
            # Check required permissions
            if required_permissions:
                user_permissions = payload.get("permissions", [])
                if not all(perm in user_permissions for perm in required_permissions):
                    self.log_event("permission_denied", {
                        "required": required_permissions,
                        "actual": user_permissions,
                        "client_info": client_info
                    })
                    return None
            
            # Log successful validation for audit
            self.log_event("session_validated", {
                "user_id": payload.get("user_id"),
                "permissions": user_permissions,
                "client_info": client_info
            })
            
            return payload
            
        except jwt.InvalidTokenError:
            self.log_event("token_invalid", {"client_info": client_info})
            return None
    
    def _is_ip_in_same_subnet(self, ip1: str, ip2: str, subnet_mask: int = 24) -> bool:
        """Check if two IPs are in the same subnet (default /24)"""
        try:
            import ipaddress
            net1 = ipaddress.IPv4Network(f"{ip1}/{subnet_mask}", strict=False)
            net2 = ipaddress.IPv4Network(f"{ip2}/{subnet_mask}", strict=False)
            return net1.network_address == net2.network_address
        except:
            return False  # Conservative: reject if we can't verify
    
    def check_rate_limit(self, user_id: str, client_info: dict) -> bool:
        """Check if user is rate limited (5 attempts per minute)"""
        
        if not redis_client:
            return False  # Skip rate limiting if Redis unavailable
        
        try:
            key = f"rate_limit:{user_id}"
            current_count = redis_client.get(key)
            
            if current_count and int(current_count) >= 5:
                return True  # Rate limited
            
            # Increment counter
            pipe = redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, 60)  # 1 minute window
            pipe.execute()
            
            return False
        except Exception as e:
            print(f"⚠️  Redis error in rate limiting: {e}")
            return False  # Skip rate limiting on Redis errors
    
    def revoke_token(self, token_fingerprint: str, reason: str = "manual_revocation"):
        """Revoke a registered token"""
        
        if token_fingerprint in self.registered_tokens:
            self.registered_tokens[token_fingerprint]["active"] = False
            
            self.log_event("token_revoked", {
                "token_fingerprint": token_fingerprint[:16],
                "reason": reason,
                "revoked_at": datetime.now().isoformat()
            })
            
            return True
        return False
    
    def log_event(self, event_type: str, details: dict):
        """Log security events"""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details,
            "server_version": API_VERSION
        }
        
        self.audit_log.append(log_entry)
        
        # In production: send to cloud logging service
        print(f"🔍 AUDIT: {event_type} - {details}")

# Global auth server instance
auth_server = AIMFAuthServer()

def require_auth(required_permissions: List[str] = None):
    """Decorator to require valid session token with strict device binding"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "Missing or invalid authorization header"}), 401
            
            token = auth_header.split(' ')[1]
            
            # Get client info for device binding validation
            client_info = {
                "ip_address": request.remote_addr,
                "user_agent": request.headers.get('User-Agent'),
                "timestamp": datetime.now().isoformat()
            }
            
            payload = auth_server.validate_session_token(token, client_info, required_permissions)
            
            if not payload:
                return jsonify({"error": "Invalid, expired, or device-mismatched session token"}), 401
            
            # Add payload to request context
            request.auth_payload = payload
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# API Endpoints

@app.route(f'/{API_VERSION}/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": API_VERSION,
        "timestamp": datetime.now().isoformat(),
        "service": "AIMF Authentication Server"
    })

@app.route(f'/{API_VERSION}/register', methods=['POST'])
def register_token_pair():
    """Register new dual NFC token pair"""
    
    data = request.get_json()
    
    required_fields = ['user_id', 'primary_nfc_hash', 'secondary_nfc_hash']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    try:
        # Convert hex hashes back to bytes for verification
        primary_nfc = bytes.fromhex(data['primary_nfc_hash'])
        secondary_nfc = bytes.fromhex(data['secondary_nfc_hash'])
        
        token_fingerprint = auth_server.register_nfc_token_pair(
            data['user_id'],
            primary_nfc,
            secondary_nfc,
            data.get('metadata', {})
        )
        
        return jsonify({
            "success": True,
            "token_fingerprint": token_fingerprint,
            "message": "NFC token pair registered successfully"
        })
        
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@app.route(f'/{API_VERSION}/authenticate', methods=['POST'])
def authenticate():
    """Authenticate with dual NFC token pair"""
    
    data = request.get_json()
    client_info = {
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get('User-Agent'),
        "timestamp": datetime.now().isoformat()
    }
    
    required_fields = ['primary_nfc_hash', 'secondary_nfc_hash']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing NFC token data"}), 400
    
    try:
        primary_nfc = bytes.fromhex(data['primary_nfc_hash'])
        secondary_nfc = bytes.fromhex(data['secondary_nfc_hash'])
        
        auth_result = auth_server.verify_nfc_token_pair(
            primary_nfc, secondary_nfc, client_info
        )
        
        if auth_result:
            return jsonify({
                "success": True,
                "session_token": auth_result["session_token"],
                "user_id": auth_result["user_id"],
                "expires_at": auth_result["expires_at"],
                "permissions": auth_result["permissions"]
            })
        else:
            return jsonify({"error": "Authentication failed"}), 401
            
    except Exception as e:
        return jsonify({"error": f"Authentication error: {str(e)}"}), 500

@app.route(f'/{API_VERSION}/validate', methods=['POST'])
@require_auth()
def validate_session():
    """Validate current session token"""
    
    return jsonify({
        "valid": True,
        "user_id": request.auth_payload["user_id"],
        "permissions": request.auth_payload["permissions"],
        "expires_at": request.auth_payload["expires_at"]
    })

@app.route(f'/{API_VERSION}/gcloud/access', methods=['POST'])
@require_auth(['gcloud_access'])
def gcloud_access():
    """Request Google Cloud access credentials"""
    
    # In production: generate temporary GCP service account tokens
    # For now: return session validation
    
    return jsonify({
        "access_granted": True,
        "user_id": request.auth_payload["user_id"],
        "valid_until": request.auth_payload["expires_at"],
        "message": "Google Cloud access authorized"
    })

@app.route(f'/{API_VERSION}/audit', methods=['GET'])
@require_auth(['admin'])
def get_audit_log():
    """Get security audit log (admin only)"""
    
    return jsonify({
        "audit_events": auth_server.audit_log[-100:],  # Last 100 events
        "total_events": len(auth_server.audit_log)
    })

if __name__ == '__main__':
    print("🔷 AIMF Authentication Server")
    print("   MobileShield NFC Chaos Writer Ecosystem")
    print(f"   API Version: {API_VERSION}")
    print()
    
    # Development server
    app.run(host='0.0.0.0', port=5000, debug=True)
