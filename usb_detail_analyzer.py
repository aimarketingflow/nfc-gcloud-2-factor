#!/usr/bin/env python3
"""
USB Device Detail Analyzer
Identifies specific details about the "generic" USB device that might be the RFID scanner
"""

import subprocess
import json
import re
from typing import List, Dict

def get_usb_details() -> str:
    """Get detailed USB device information"""
    try:
        result = subprocess.run(['system_profiler', 'SPUSBDataType'], 
                              capture_output=True, text=True, timeout=30)
        return result.stdout
    except Exception as e:
        return f"Error getting USB details: {e}"

def parse_usb_devices(usb_output: str) -> List[Dict]:
    """Parse USB output into structured device information"""
    devices = []
    current_device = {}
    
    lines = usb_output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Device name (main entries)
        if line and not line.startswith(' ') and ':' in line:
            if current_device:
                devices.append(current_device)
            current_device = {
                'name': line.replace(':', ''),
                'details': {}
            }
        
        # Device details (indented lines)
        elif line and ':' in line and current_device:
            key, value = line.split(':', 1)
            current_device['details'][key.strip()] = value.strip()
    
    # Add the last device
    if current_device:
        devices.append(current_device)
    
    return devices

def identify_suspicious_devices(devices: List[Dict]) -> List[Dict]:
    """Identify potentially suspicious or generic devices"""
    suspicious = []
    
    # Keywords that might indicate RFID/NFC devices
    rfid_keywords = [
        'rfid', 'nfc', 'reader', 'card', 'acr122', 'contactless',
        'smart', 'proximity', 'mifare', 'iso14443', 'felica'
    ]
    
    # Generic/suspicious indicators
    generic_indicators = [
        'generic', 'unknown', 'unidentified', 'composite',
        'hid', 'human interface', 'vendor-specific'
    ]
    
    for device in devices:
        name_lower = device['name'].lower()
        details_str = str(device['details']).lower()
        
        # Check for RFID/NFC indicators
        is_rfid_related = any(keyword in name_lower or keyword in details_str 
                             for keyword in rfid_keywords)
        
        # Check for generic indicators
        is_generic = any(indicator in name_lower or indicator in details_str 
                        for indicator in generic_indicators)
        
        # Look for specific vendor/product IDs that might be RFID readers
        vendor_id = device['details'].get('Vendor ID', '').lower()
        product_id = device['details'].get('Product ID', '').lower()
        
        # Common RFID reader vendor IDs
        known_rfid_vendors = [
            '072f',  # ACS (Advanced Card Systems)
            '04e6',  # SCM Microsystems
            '0b97',  # O2Micro
            '413c',  # Dell (some models)
            '076b',  # OmniKey/HID Global
        ]
        
        is_known_rfid_vendor = any(vid in vendor_id for vid in known_rfid_vendors)
        
        if is_rfid_related or is_generic or is_known_rfid_vendor:
            device['analysis'] = {
                'is_rfid_related': is_rfid_related,
                'is_generic': is_generic,
                'is_known_rfid_vendor': is_known_rfid_vendor,
                'suspicion_level': 'HIGH' if is_rfid_related else ('MEDIUM' if is_generic else 'LOW')
            }
            suspicious.append(device)
    
    return suspicious

def main():
    """Main analysis function"""
    print("🔍 USB DEVICE DETAIL ANALYZER")
    print("=" * 50)
    
    # Get USB device information
    print("📊 Retrieving USB device details...")
    usb_output = get_usb_details()
    
    if "Error" in usb_output:
        print(f"❌ {usb_output}")
        return
    
    # Parse devices
    devices = parse_usb_devices(usb_output)
    print(f"📱 Found {len(devices)} USB devices")
    
    # Identify suspicious devices
    suspicious_devices = identify_suspicious_devices(devices)
    
    print(f"\n🚨 SUSPICIOUS/GENERIC DEVICES: {len(suspicious_devices)}")
    print("=" * 50)
    
    for i, device in enumerate(suspicious_devices, 1):
        print(f"\n🔍 DEVICE #{i}: {device['name']}")
        print("-" * 40)
        
        # Show analysis
        analysis = device.get('analysis', {})
        print(f"📊 Suspicion Level: {analysis.get('suspicion_level', 'UNKNOWN')}")
        print(f"🔧 RFID Related: {analysis.get('is_rfid_related', False)}")
        print(f"⚠️  Generic Device: {analysis.get('is_generic', False)}")
        print(f"🏷️  Known RFID Vendor: {analysis.get('is_known_rfid_vendor', False)}")
        
        # Show device details
        print("\n📋 Device Details:")
        for key, value in device['details'].items():
            if key in ['Vendor ID', 'Product ID', 'Version', 'Speed', 'Manufacturer', 'Location ID']:
                print(f"   {key}: {value}")
    
    # Show all devices for reference
    print(f"\n📝 ALL USB DEVICES ({len(devices)}):")
    print("=" * 50)
    for i, device in enumerate(devices, 1):
        vendor_id = device['details'].get('Vendor ID', 'N/A')
        product_id = device['details'].get('Product ID', 'N/A')
        print(f"{i:2d}. {device['name'][:50]:<50} | VID: {vendor_id} | PID: {product_id}")
    
    # Save detailed report
    report = {
        'scan_time': '2025-08-26T13:42:00',
        'total_devices': len(devices),
        'suspicious_devices': suspicious_devices,
        'all_devices': devices
    }
    
    with open('usb_device_analysis.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n💾 Detailed report saved: usb_device_analysis.json")
    
    # Recommendations
    print(f"\n🔧 RECOMMENDATIONS:")
    if not suspicious_devices:
        print("   ✅ No obviously suspicious USB devices detected")
        print("   ⚠️  RFID scanner may not be connected or recognized")
    else:
        for device in suspicious_devices:
            if device['analysis']['is_rfid_related']:
                print(f"   🎯 Investigate: {device['name']} - Potential RFID device")
            elif device['analysis']['is_generic']:
                print(f"   ⚠️  Check: {device['name']} - Generic device, could be RFID scanner")

if __name__ == "__main__":
    main()
