#!/usr/bin/env python3
"""
RFID Hardware Detector
Identifies connected RFID/NFC readers using multiple methods

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

import os
import subprocess
import glob

def check_usb_devices():
    """Check USB devices via system calls"""
    print("🔍 Checking USB devices...")
    
    try:
        # Try system_profiler with specific USB data
        result = subprocess.run(['system_profiler', 'SPUSBDataType', '-xml'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and 'USB' in result.stdout:
            print("✅ USB system info available")
            # Look for common RFID/NFC keywords
            keywords = ['rfid', 'nfc', 'reader', 'card', 'smart', 'acr', 'acs', 'ch340', 'ch341', 'cp210', 'ft232']
            for keyword in keywords:
                if keyword.lower() in result.stdout.lower():
                    print(f"   Found keyword: {keyword}")
        else:
            print("⚠️  USB system info unavailable")
            
    except Exception as e:
        print(f"❌ USB check failed: {e}")

def check_serial_ports():
    """Check for serial port devices"""
    print("\n🔌 Checking serial ports...")
    
    # Common serial device patterns on macOS
    serial_patterns = [
        '/dev/tty.usbserial*',
        '/dev/tty.usbmodem*', 
        '/dev/cu.usbserial*',
        '/dev/cu.usbmodem*',
        '/dev/tty.wchusbserial*',
        '/dev/cu.wchusbserial*'
    ]
    
    found_devices = []
    
    for pattern in serial_patterns:
        devices = glob.glob(pattern)
        if devices:
            found_devices.extend(devices)
    
    if found_devices:
        print(f"✅ Found {len(found_devices)} serial device(s):")
        for device in found_devices:
            print(f"   - {device}")
        return found_devices
    else:
        print("❌ No serial devices found")
        return []

def check_with_python_serial():
    """Check serial ports using Python serial library"""
    print("\n📡 Checking with Python serial...")
    
    try:
        import serial.tools.list_ports
        
        ports = serial.tools.list_ports.comports()
        
        if ports:
            print(f"✅ Found {len(ports)} serial port(s):")
            for port in ports:
                print(f"   - {port.device}")
                print(f"     Description: {port.description}")
                print(f"     VID:PID: {port.vid:04X}:{port.pid:04X}" if port.vid else "     VID:PID: Unknown")
                print(f"     Manufacturer: {port.manufacturer or 'Unknown'}")
                
                # Check for RFID/NFC related keywords
                description_lower = (port.description or '').lower()
                manufacturer_lower = (port.manufacturer or '').lower()
                
                rfid_keywords = ['rfid', 'nfc', 'reader', 'card', 'smart', 'ch340', 'ch341', 'cp210', 'ft232', 'uart']
                
                for keyword in rfid_keywords:
                    if keyword in description_lower or keyword in manufacturer_lower:
                        print(f"     🎯 POTENTIAL RFID READER (keyword: {keyword})")
                        break
                print()
            return ports
        else:
            print("❌ No serial ports detected")
            return []
            
    except ImportError:
        print("❌ pyserial not available")
        print("   Install with: pip install pyserial")
        return []
    except Exception as e:
        print(f"❌ Serial check failed: {e}")
        return []

def check_smart_card_readers():
    """Check for smart card readers (PC/SC)"""
    print("\n💳 Checking smart card readers...")
    
    try:
        from smartcard.System import readers
        from smartcard.Exceptions import NoCardException, CardConnectionException
        
        reader_list = readers()
        
        if reader_list:
            print(f"✅ Found {len(reader_list)} smart card reader(s):")
            for i, reader in enumerate(reader_list):
                print(f"   {i+1}. {reader}")
                
                # Try to connect to each reader
                try:
                    connection = reader.createConnection()
                    connection.connect()
                    print(f"      ✅ Connection successful")
                    
                    # Try to detect if a card is present
                    try:
                        response, sw1, sw2 = connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                        if sw1 == 0x90 and sw2 == 0x00:
                            print(f"      📱 Card detected: {bytes(response).hex()}")
                        else:
                            print(f"      ⚪ No card present")
                    except Exception:
                        print(f"      ⚪ No card present")
                        
                    connection.disconnect()
                    
                except Exception as e:
                    print(f"      ❌ Connection failed: {e}")
                    
            return reader_list
        else:
            print("❌ No smart card readers found")
            return []
            
    except ImportError:
        print("❌ pyscard not available")
        print("   Install with: pip install pyscard")
        return []
    except Exception as e:
        print(f"❌ Smart card check failed: {e}")
        return []

def main():
    """Main hardware detection"""
    print("🔷 AIMF RFID Hardware Detector")
    print("   Scanning for connected RFID/NFC readers...")
    print()
    
    # Run all detection methods
    check_usb_devices()
    serial_devices = check_serial_ports()
    serial_ports = check_with_python_serial()
    smart_readers = check_smart_card_readers()
    
    print("\n" + "="*50)
    print("📋 DETECTION SUMMARY")
    print("="*50)
    
    if smart_readers:
        print("🎯 RECOMMENDED: Use smart card readers for NFC/RFID")
        print("   These are compatible with our pyscard-based system")
        for reader in smart_readers:
            print(f"   - {reader}")
    
    elif serial_ports:
        print("🔧 ALTERNATIVE: Serial-based RFID readers detected")
        print("   May require custom serial communication code")
        for port in serial_ports:
            if any(keyword in (port.description or '').lower() for keyword in ['rfid', 'nfc', 'reader', 'ch340', 'ch341']):
                print(f"   - {port.device} ({port.description})")
    
    elif serial_devices:
        print("⚠️  Serial devices found, but need identification")
        print("   Try connecting and testing each device")
        for device in serial_devices:
            print(f"   - {device}")
    
    else:
        print("❌ NO RFID/NFC READERS DETECTED")
        print("   Check:")
        print("   - Device is connected via USB")
        print("   - Drivers are installed")
        print("   - Device appears in System Information")
    
    print("\nNext steps:")
    if smart_readers:
        print("✅ Ready to test NFC authentication")
        print("   Run: python3 simple_nfc_test.py")
    else:
        print("🔧 Need to configure RFID reader first")
        print("   Check device documentation for setup")

if __name__ == "__main__":
    main()
