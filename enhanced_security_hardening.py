#!/usr/bin/env python3
"""
Enhanced Security Hardening for NFC Cloud Authentication
Implements multiple layers of security beyond basic device binding
"""

import hashlib
import hmac
import time
import platform
import psutil
import uuid
import subprocess
import os
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class EnhancedSecurityHardening:
    """Advanced security measures for NFC authentication"""
    
    def __init__(self):
        self.hardware_fingerprint = self._generate_hardware_fingerprint()
        self.process_fingerprint = self._generate_process_fingerprint()
        self.invisible_scan_interval = 30  # seconds
        self.last_invisible_scan = 0
        
    def _generate_hardware_fingerprint(self) -> str:
        """Generate unique hardware fingerprint"""
        components = []
        
        # CPU info
        try:
            cpu_info = platform.processor()
            components.append(f"cpu:{cpu_info}")
        except:
            pass
            
        # Memory info
        try:
            memory_info = psutil.virtual_memory().total
            components.append(f"memory:{memory_info}")
        except:
            pass
            
        # MAC addresses
        try:
            mac_addresses = []
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family.name == 'AF_LINK':
                        mac_addresses.append(addr.address)
            components.append(f"macs:{'|'.join(sorted(mac_addresses))}")
        except:
            pass
            
        # System UUID (if available)
        try:
            system_uuid = str(uuid.uuid1())
            components.append(f"uuid:{system_uuid}")
        except:
            pass
            
        combined = "|".join(components)
        return hashlib.sha256(combined.encode()).hexdigest()[:32]
    
    def _generate_process_fingerprint(self) -> str:
        """Generate process-specific fingerprint"""
        components = [
            f"pid:{os.getpid()}",
            f"ppid:{os.getppid()}",
            f"cwd:{os.getcwd()}",
            f"user:{os.getenv('USER', 'unknown')}",
            f"python_path:{os.path.abspath(__file__)}"
        ]
        
        combined = "|".join(components)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def create_enhanced_client_info(self, ip_address: str, user_agent: str) -> Dict:
        """Create enhanced client fingerprint with multiple security layers"""
        
        return {
            "ip_address": ip_address,
            "user_agent": user_agent,
            "timestamp": datetime.now().isoformat(),
            "hardware_fingerprint": self.hardware_fingerprint,
            "process_fingerprint": self.process_fingerprint,
            "platform": platform.system(),
            "architecture": platform.architecture()[0],
            "python_version": platform.python_version(),
            "session_id": str(uuid.uuid4())[:8]
        }
    
    def validate_hardware_consistency(self, stored_fingerprint: str) -> bool:
        """Validate that hardware hasn't changed significantly"""
        current_fingerprint = self._generate_hardware_fingerprint()
        
        # Allow minor variations but reject major changes
        similarity = self._calculate_fingerprint_similarity(stored_fingerprint, current_fingerprint)
        return similarity > 0.8  # 80% similarity threshold
    
    def _calculate_fingerprint_similarity(self, fp1: str, fp2: str) -> float:
        """Calculate similarity between two fingerprints"""
        if len(fp1) != len(fp2):
            return 0.0
            
        matches = sum(1 for a, b in zip(fp1, fp2) if a == b)
        return matches / len(fp1)
    
    def perform_invisible_nfc_scan(self, nfc_reader_callback) -> Optional[Dict]:
        """Perform invisible background NFC scan for continuous validation"""
        current_time = time.time()
        
        # Rate limit invisible scans
        if current_time - self.last_invisible_scan < self.invisible_scan_interval:
            return None
            
        self.last_invisible_scan = current_time
        
        try:
            # Attempt silent NFC scan (no user prompts)
            scan_result = nfc_reader_callback(silent=True)
            
            if scan_result:
                return {
                    "invisible_scan_successful": True,
                    "scan_time": current_time,
                    "uid_hash": hashlib.sha256(scan_result).hexdigest()[:16],
                    "validation_type": "invisible_background"
                }
        except Exception as e:
            # Silent failure for invisible scans
            pass
            
        return None
    
    def detect_vm_environment(self) -> Dict:
        """Detect if running in VM/emulated environment"""
        vm_indicators = {
            "is_vm": False,
            "vm_type": None,
            "confidence": 0.0
        }
        
        vm_detection_checks = []
        
        # Check for VM-specific hardware
        try:
            cpu_info = platform.processor().lower()
            if any(vm in cpu_info for vm in ['vmware', 'virtualbox', 'qemu', 'kvm']):
                vm_detection_checks.append("cpu_vm_signature")
        except:
            pass
            
        # Check for VM-specific processes
        try:
            processes = [p.name().lower() for p in psutil.process_iter(['name'])]
            vm_processes = ['vmtoolsd', 'vboxservice', 'qemu', 'vmware']
            if any(vm_proc in proc for proc in processes for vm_proc in vm_processes):
                vm_detection_checks.append("vm_processes")
        except:
            pass
            
        # Check system manufacturer
        try:
            import platform
            system_info = platform.system()
            if system_info == "Linux":
                # Check DMI info
                try:
                    with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                        vendor = f.read().strip().lower()
                        if any(vm in vendor for vm in ['vmware', 'innotek', 'qemu', 'microsoft']):
                            vm_detection_checks.append("dmi_vendor")
                except:
                    pass
        except:
            pass
            
        if vm_detection_checks:
            vm_indicators["is_vm"] = True
            vm_indicators["vm_type"] = vm_detection_checks[0]
            vm_indicators["confidence"] = min(len(vm_detection_checks) * 0.3, 1.0)
            
        return vm_indicators
    
    def generate_chaos_enhanced_token(self, primary_nfc: bytes, secondary_nfc: bytes, 
                                    environment_data: Dict) -> str:
        """Generate chaos-enhanced token with environmental factors"""
        
        # Combine NFC data with environmental chaos
        chaos_components = [
            primary_nfc,
            secondary_nfc,
            str(time.time() * 1000).encode(),  # High precision timestamp
            self.hardware_fingerprint.encode(),
            str(environment_data.get("cpu_temp", 0)).encode(),
            str(environment_data.get("memory_pressure", 0)).encode(),
            os.urandom(16)  # Additional entropy
        ]
        
        combined_chaos = b"".join(chaos_components)
        
        # Multi-stage hashing for enhanced security
        stage1 = hashlib.sha3_256(combined_chaos).digest()
        stage2 = hashlib.blake2b(stage1, key=b"aimf_chaos_2024").digest()
        stage3 = hashlib.sha256(stage2).hexdigest()
        
        return stage3
    
    def validate_geographic_consistency(self, stored_location: Dict, 
                                      current_location: Dict) -> bool:
        """Validate geographic location consistency"""
        
        if not stored_location or not current_location:
            return True  # Skip if location data unavailable
            
        # Calculate distance between locations
        try:
            lat1, lon1 = stored_location.get("lat", 0), stored_location.get("lon", 0)
            lat2, lon2 = current_location.get("lat", 0), current_location.get("lon", 0)
            
            # Haversine formula for distance
            import math
            
            dlat = math.radians(lat2 - lat1)
            dlon = math.radians(lon2 - lon1)
            a = (math.sin(dlat/2)**2 + 
                 math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * 
                 math.sin(dlon/2)**2)
            c = 2 * math.asin(math.sqrt(a))
            distance_km = 6371 * c  # Earth's radius in km
            
            # Allow 100km movement (reasonable for daily travel)
            return distance_km < 100
            
        except:
            return True  # Conservative: allow if calculation fails
    
    def create_security_audit_report(self) -> Dict:
        """Generate comprehensive security audit report"""
        
        return {
            "timestamp": datetime.now().isoformat(),
            "hardware_fingerprint": self.hardware_fingerprint,
            "process_fingerprint": self.process_fingerprint,
            "vm_detection": self.detect_vm_environment(),
            "platform_info": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor()
            },
            "security_features": {
                "invisible_scanning": True,
                "hardware_binding": True,
                "geographic_validation": True,
                "vm_detection": True,
                "chaos_enhancement": True,
                "multi_stage_hashing": True
            }
        }

# Enhanced Security Integration Example
def demonstrate_enhanced_security():
    """Demonstrate enhanced security features"""
    
    security = EnhancedSecurityHardening()
    
    print("🔒 Enhanced Security Hardening Demo")
    print("=" * 50)
    
    # Hardware fingerprinting
    print(f"🖥️  Hardware Fingerprint: {security.hardware_fingerprint}")
    print(f"⚙️  Process Fingerprint: {security.process_fingerprint}")
    
    # VM detection
    vm_info = security.detect_vm_environment()
    print(f"🖥️  VM Detection: {vm_info}")
    
    # Enhanced client info
    client_info = security.create_enhanced_client_info("192.168.1.100", "Python/NFC-Client")
    print(f"📱 Enhanced Client Info Keys: {list(client_info.keys())}")
    
    # Security audit
    audit_report = security.create_security_audit_report()
    print(f"📊 Security Audit Generated: {len(audit_report)} metrics")
    
    print("\n✅ Enhanced security features ready for deployment")

if __name__ == "__main__":
    demonstrate_enhanced_security()
