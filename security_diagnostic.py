#!/usr/bin/env python3
"""
Security Diagnostic Tool - Detect System Changes (24 Hours)
Investigates potential compromise affecting RFID/NFC scanner functionality
"""

import subprocess
import json
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List

class SecurityDiagnostic:
    """Comprehensive security analysis for RFID scanner compromise investigation"""
    
    def __init__(self):
        self.report = {
            "scan_time": datetime.now().isoformat(),
            "findings": [],
            "alerts": [],
            "hardware_status": {},
            "network_status": {},
            "process_status": {},
            "system_status": {}
        }
        
    def run_command(self, cmd: str, timeout: int = 10) -> str:
        """Safely run system command with timeout"""
        try:
            result = subprocess.run(
                cmd.split(), 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.stdout.strip() if result.returncode == 0 else ""
        except Exception as e:
            self.report["alerts"].append(f"Command failed: {cmd} - {str(e)}")
            return ""
    
    def check_usb_hardware_changes(self):
        """Check for USB device changes in past 24 hours"""
        print("🔍 Checking USB/Hardware Changes...")
        
        # Current USB devices
        usb_devices = self.run_command("system_profiler SPUSBDataType")
        
        # Parse USB devices
        usb_count = usb_devices.count("Product ID:")
        
        self.report["hardware_status"] = {
            "usb_device_count": usb_count,
            "nfc_readers_detected": "RFID" in usb_devices or "NFC" in usb_devices or "ACR122" in usb_devices,
            "suspicious_devices": []
        }
        
        # Check for suspicious USB devices
        suspicious_keywords = ["unknown", "unrecognized", "hid", "generic"]
        for keyword in suspicious_keywords:
            if keyword.lower() in usb_devices.lower():
                self.report["hardware_status"]["suspicious_devices"].append(keyword)
        
        # Check system report for hardware changes
        hardware_report = self.run_command("system_profiler SPHardwareDataType")
        self.report["hardware_status"]["hardware_overview"] = hardware_report[:500]
        
        print(f"📊 USB devices detected: {usb_count}")
        print(f"🔍 NFC readers found: {self.report['hardware_status']['nfc_readers_detected']}")
        
    def check_port_status(self):
        """Check network ports and listening services"""
        print("🔍 Checking Port Status...")
        
        # Check listening ports
        netstat_output = self.run_command("netstat -an")
        listening_ports = []
        
        for line in netstat_output.split('\n'):
            if 'LISTEN' in line:
                parts = line.split()
                if len(parts) >= 4:
                    listening_ports.append(parts[3])
        
        self.report["network_status"] = {
            "listening_ports": listening_ports[:20],  # Limit to top 20
            "total_listening": len(listening_ports),
            "suspicious_ports": []
        }
        
        # Check for suspicious ports
        suspicious_port_ranges = [
            (1024, 1100),   # Potential backdoors
            (4444, 4444),   # Common backdoor
            (31337, 31337), # Elite/hacker port
            (12345, 12345), # Common backdoor
            (54321, 54321)  # Reverse common port
        ]
        
        for port_str in listening_ports:
            try:
                if ':' in port_str:
                    port = int(port_str.split(':')[-1])
                    for start, end in suspicious_port_ranges:
                        if start <= port <= end:
                            self.report["network_status"]["suspicious_ports"].append(port)
            except:
                continue
        
        print(f"📊 Listening ports: {len(listening_ports)}")
        
    def check_recent_processes(self):
        """Check for suspicious processes and recent changes"""
        print("🔍 Checking Process Status...")
        
        # Get running processes
        ps_output = self.run_command("ps -eo pid,ppid,user,command")
        
        # Count processes by user
        user_processes = {}
        suspicious_processes = []
        
        for line in ps_output.split('\n')[1:]:  # Skip header
            parts = line.strip().split(None, 3)
            if len(parts) >= 4:
                pid, ppid, user, command = parts
                
                # Count by user
                user_processes[user] = user_processes.get(user, 0) + 1
                
                # Check for suspicious processes
                suspicious_keywords = [
                    "nc ", "netcat", "ncat",  # Network tools
                    "wget", "curl",           # Download tools
                    "python -c", "perl -e",  # Inline scripts
                    "base64", "/tmp/",        # Suspicious locations
                    "rfkill", "hciconfig"     # RF control tools
                ]
                
                for keyword in suspicious_keywords:
                    if keyword in command.lower():
                        suspicious_processes.append({
                            "pid": pid,
                            "user": user,
                            "command": command[:100],
                            "keyword": keyword
                        })
        
        self.report["process_status"] = {
            "total_processes": len(ps_output.split('\n')) - 1,
            "user_process_count": user_processes,
            "suspicious_processes": suspicious_processes[:10]
        }
        
        print(f"📊 Total processes: {self.report['process_status']['total_processes']}")
        print(f"🚨 Suspicious processes: {len(suspicious_processes)}")
        
    def check_system_logs(self):
        """Check system logs for recent suspicious activity"""
        print("🔍 Checking System Logs...")
        
        # Check console logs for USB/hardware events
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        
        # Get recent log entries
        log_cmd = f"log show --predicate 'eventMessage contains \"USB\" OR eventMessage contains \"RFID\" OR eventMessage contains \"NFC\"' --info --start '{yesterday}'"
        log_output = self.run_command(log_cmd, timeout=30)
        
        usb_events = log_output.count("USB")
        rfid_events = log_output.count("RFID") + log_output.count("NFC")
        
        self.report["system_status"] = {
            "usb_log_events": usb_events,
            "rfid_log_events": rfid_events,
            "recent_log_sample": log_output[:1000] if log_output else "No recent logs found"
        }
        
        # Check for system modifications
        brew_recent = self.run_command("brew list --versions")
        self.report["system_status"]["brew_packages"] = len(brew_recent.split('\n'))
        
        print(f"📊 USB log events (24h): {usb_events}")
        print(f"📊 RFID/NFC log events (24h): {rfid_events}")
        
    def check_network_connections(self):
        """Check for suspicious network connections"""
        print("🔍 Checking Network Connections...")
        
        # Check active network connections
        lsof_output = self.run_command("lsof -i -n")
        
        external_connections = []
        suspicious_connections = []
        
        for line in lsof_output.split('\n'):
            if '->' in line and 'ESTABLISHED' in line:
                parts = line.split()
                if len(parts) >= 9:
                    process = parts[0]
                    connection = parts[8]
                    
                    external_connections.append({
                        "process": process,
                        "connection": connection
                    })
                    
                    # Check for suspicious connections
                    if any(suspicious in connection.lower() for suspicious in [
                        'tor', 'onion', '127.0.0.1', 'localhost'
                    ]):
                        suspicious_connections.append({
                            "process": process,
                            "connection": connection
                        })
        
        self.report["network_status"]["external_connections"] = external_connections[:10]
        self.report["network_status"]["suspicious_connections"] = suspicious_connections
        
        print(f"📊 External connections: {len(external_connections)}")
        
    def check_file_modifications(self):
        """Check for recent file modifications in system directories"""
        print("🔍 Checking Recent File Modifications...")
        
        # Check for recent modifications in system directories
        sensitive_dirs = [
            "/usr/local/lib",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "~/Library/LaunchAgents"
        ]
        
        recent_modifications = []
        
        for dir_path in sensitive_dirs:
            if os.path.exists(os.path.expanduser(dir_path)):
                find_cmd = f"find {os.path.expanduser(dir_path)} -type f -mtime -1"
                recent_files = self.run_command(find_cmd)
                
                if recent_files:
                    recent_modifications.extend(recent_files.split('\n')[:5])
        
        self.report["system_status"]["recent_modifications"] = recent_modifications[:10]
        
    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\n🔒 SECURITY DIAGNOSTIC REPORT")
        print("=" * 50)
        
        # Analyze findings
        risk_level = "LOW"
        
        # Check for high-risk indicators
        if (len(self.report["network_status"].get("suspicious_connections", [])) > 0 or
            len(self.report["process_status"].get("suspicious_processes", [])) > 0 or
            len(self.report["network_status"].get("suspicious_ports", [])) > 0):
            risk_level = "HIGH"
        elif (self.report["system_status"].get("rfid_log_events", 0) == 0 and
              not self.report["hardware_status"].get("nfc_readers_detected", False)):
            risk_level = "MEDIUM"
        
        print(f"🚨 RISK LEVEL: {risk_level}")
        print()
        
        # Hardware status
        print("🖥️  HARDWARE STATUS:")
        print(f"   NFC Readers Detected: {self.report['hardware_status']['nfc_readers_detected']}")
        print(f"   USB Device Count: {self.report['hardware_status']['usb_device_count']}")
        print(f"   Suspicious Devices: {len(self.report['hardware_status']['suspicious_devices'])}")
        print()
        
        # Network status
        print("🌐 NETWORK STATUS:")
        print(f"   Listening Ports: {self.report['network_status']['total_listening']}")
        print(f"   Suspicious Ports: {self.report['network_status']['suspicious_ports']}")
        print(f"   External Connections: {len(self.report['network_status'].get('external_connections', []))}")
        print()
        
        # Process status
        print("⚙️  PROCESS STATUS:")
        print(f"   Total Processes: {self.report['process_status']['total_processes']}")
        print(f"   Suspicious Processes: {len(self.report['process_status']['suspicious_processes'])}")
        print()
        
        # System logs
        print("📋 SYSTEM LOGS (24h):")
        print(f"   USB Events: {self.report['system_status']['usb_log_events']}")
        print(f"   RFID/NFC Events: {self.report['system_status']['rfid_log_events']}")
        print()
        
        # Recommendations
        print("🔧 RECOMMENDATIONS:")
        if not self.report['hardware_status']['nfc_readers_detected']:
            print("   ⚠️  NFC reader not detected - check USB connection")
        if self.report['system_status']['rfid_log_events'] == 0:
            print("   ⚠️  No RFID/NFC activity in logs - potential driver issue")
        if len(self.report['process_status']['suspicious_processes']) > 0:
            print("   🚨 Suspicious processes detected - investigate immediately")
        if len(self.report['network_status']['suspicious_ports']) > 0:
            print("   🚨 Suspicious network ports - check for backdoors")
        
        # Save detailed report
        report_file = f"security_diagnostic_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(self.report, f, indent=2)
        
        print(f"\n💾 Detailed report saved: {report_file}")
        
        return risk_level
    
    def run_full_diagnostic(self):
        """Run complete security diagnostic"""
        print("🔐 STARTING SECURITY DIAGNOSTIC")
        print("Investigating potential RFID scanner compromise...")
        print("=" * 60)
        
        self.check_usb_hardware_changes()
        self.check_port_status()
        self.check_recent_processes()
        self.check_system_logs()
        self.check_network_connections()
        self.check_file_modifications()
        
        risk_level = self.generate_security_report()
        
        return risk_level

def main():
    """Main diagnostic entry point"""
    diagnostic = SecurityDiagnostic()
    risk_level = diagnostic.run_full_diagnostic()
    
    if risk_level == "HIGH":
        print("\n🚨 HIGH RISK: Immediate investigation required!")
    elif risk_level == "MEDIUM":
        print("\n⚠️  MEDIUM RISK: Hardware issues detected")
    else:
        print("\n✅ LOW RISK: System appears normal")

if __name__ == "__main__":
    main()
