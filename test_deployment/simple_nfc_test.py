#!/usr/bin/env python3
"""
Simple NFC Reader Test
Tests basic NFC reader connectivity

AIMF LLC - MobileShield NFC Chaos Writer Ecosystem
"""

def test_nfc_reader():
    """Test basic NFC reader functionality"""
    
    print("🔍 Testing NFC Reader Hardware")
    print()
    
    try:
        from smartcard.System import readers
        from smartcard.util import toHexString
        
        print("✅ pyscard library imported successfully")
        
        # Check for readers
        reader_list = readers()
        
        if not reader_list:
            print("❌ No NFC readers detected")
            print("   Check:")
            print("   - NFC reader is connected via USB")
            print("   - Reader drivers are installed")
            print("   - Reader shows up in System Information")
            return False
        
        print(f"✅ Found {len(reader_list)} NFC reader(s):")
        for i, reader in enumerate(reader_list):
            print(f"   {i+1}. {reader}")
        
        # Test connection to first reader
        reader = reader_list[0]
        print(f"\n🔌 Testing connection to: {reader}")
        
        try:
            connection = reader.createConnection()
            connection.connect()
            print("✅ Connection established")
            
            print("\n📱 Place an NFC tag on the reader and press Enter...")
            input()
            
            # Try to read card UID
            response, sw1, sw2 = connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            
            if sw1 == 0x90 and sw2 == 0x00:
                uid = toHexString(response)
                print(f"✅ NFC tag detected!")
                print(f"   UID: {uid}")
                print(f"   Raw data: {response}")
                
                # Convert to bytes for our system
                uid_bytes = bytes(response)
                print(f"   Bytes: {uid_bytes.hex()}")
                
                return True
            else:
                print(f"❌ Failed to read NFC tag")
                print(f"   Status: {sw1:02X} {sw2:02X}")
                return False
                
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Install pyscard: pip install pyscard")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    print("🔷 AIMF NFC Reader Hardware Test")
    print()
    
    success = test_nfc_reader()
    
    if success:
        print("\n🎉 NFC Reader Test PASSED!")
        print("   Hardware is working correctly")
        print("   Ready for dual NFC registration")
    else:
        print("\n❌ NFC Reader Test FAILED")
        print("   Fix hardware issues before proceeding")
        exit(1)
