#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import requests
from pathlib import Path

class IPSTester:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.dashboard_url = "http://localhost:5000"
        self.alert_file = self.base_dir / "alert_fast.txt"
        self.log_file = self.base_dir / "ips.log"

    def test_setup(self):
        """Test if all required files and directories exist"""
        print("\n=== Testing Setup ===")
        required_files = [
            "main.py",
            "setup_ips.sh",
            "config/snort.lua",
            "config/rules/local.rules",
            "dashboard/app.py",
            "dashboard/templates/index.html"
        ]
        
        for file in required_files:
            path = self.base_dir / file
            if path.exists():
                print(f"✓ {file} exists")
            else:
                print(f"✗ {file} is missing")
                return False
        return True

    def test_snort_rules(self):
        """Test if Snort rules are valid"""
        print("\n=== Testing Snort Rules ===")
        try:
            result = subprocess.run(
                ["snort", "-c", str(self.base_dir / "config/snort.lua")],
                capture_output=True,
                text=True
            )
            if "ERROR" in result.stderr:
                print("✗ Snort rules have errors")
                print(result.stderr)
                return False
            print("✓ Snort rules are valid")
            return True
        except FileNotFoundError:
            print("✗ Snort is not installed")
            return False

    def test_dashboard(self):
        """Test if the dashboard is accessible"""
        print("\n=== Testing Dashboard ===")
        try:
            response = requests.get(self.dashboard_url)
            if response.status_code == 200:
                print("✓ Dashboard is accessible")
                return True
            else:
                print(f"✗ Dashboard returned status code {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("✗ Dashboard is not running")
            return False

    def test_alert_generation(self):
        """Test if alerts are being generated"""
        print("\n=== Testing Alert Generation ===")
        # Create a test alert
        with open(self.alert_file, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [**] [1:1000001:1] Test Alert [**] [Classification: Potentially Bad Traffic] [Priority: 2] {time.time()}\n")
        
        # Wait for alert to be processed
        time.sleep(2)
        
        # Check if alert was logged
        if self.log_file.exists():
            with open(self.log_file, "r") as f:
                if "Test Alert" in f.read():
                    print("✓ Alerts are being generated and logged")
                    return True
        print("✗ Alert generation failed")
        return False

    def test_firewall_rules(self):
        """Test if firewall rules are being updated"""
        print("\n=== Testing Firewall Rules ===")
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "IPS_BLOCK"],
                capture_output=True,
                text=True
            )
            if "IPS_BLOCK" in result.stdout:
                print("✓ Firewall rules are present")
                return True
            print("✗ Firewall rules are missing")
            return False
        except subprocess.CalledProcessError:
            print("✗ Failed to check firewall rules")
            return False

    def run_all_tests(self):
        """Run all tests and return overall status"""
        tests = [
            self.test_setup,
            self.test_snort_rules,
            self.test_dashboard,
            self.test_alert_generation,
            self.test_firewall_rules
        ]
        
        results = []
        for test in tests:
            try:
                result = test()
                results.append(result)
            except Exception as e:
                print(f"✗ Test {test.__name__} failed with error: {str(e)}")
                results.append(False)
        
        success_count = sum(1 for r in results if r)
        print(f"\n=== Test Summary ===")
        print(f"Passed: {success_count}/{len(tests)} tests")
        return all(results)

if __name__ == "__main__":
    tester = IPSTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1) 