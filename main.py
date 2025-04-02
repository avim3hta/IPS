import os
import sys
import time
import logging
import subprocess
from datetime import datetime
from pathlib import Path
import threading
import queue

# Configure logging
logger = logging.getLogger('IPS')
logger.setLevel(logging.INFO)

# Create handlers
console_handler = logging.StreamHandler(sys.stdout)
file_handler = logging.FileHandler('logs/ips.log')

# Create formatters and add it to handlers
log_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(log_format)
file_handler.setFormatter(log_format)

# Add handlers to the logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

class IPS:
    def __init__(self):
        self.config_dir = Path('config')
        self.rules_dir = Path('rules')
        self.logs_dir = Path('logs')
        self.snort_config = self.config_dir / 'snort.lua'
        self.local_rules = self.rules_dir / 'local.rules'
        self.alert_file = Path('alert_fast.txt')
        self.alert_queue = queue.Queue()
        self.blocked_ips = set()
        self.packet_count = 0
        
        # Create necessary directories
        self._create_directories()
        
        # Initialize Snort configuration
        self._init_snort_config()
        
        # Initialize rules
        self._init_rules()

    def _create_directories(self):
        """Create necessary directories if they don't exist."""
        for directory in [self.config_dir, self.rules_dir, self.logs_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")

    def _init_snort_config(self):
        """Initialize Snort configuration file."""
        if not self.snort_config.exists():
            config_content = '''-- Snort 3.0 configuration

-- Network variables
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Basic configuration
daq = {
    module_dirs = {
        '/usr/local/lib/daq'
    },
    modules = {
        {
            name = 'afpacket',
            mode = 'passive'
        }
    }
}

-- Configure alerts
alerts = {
    alert_with_interface_name = true,
    detection_filter_memcap = 1048576,
    event_filter_memcap = 1048576,
    log_references = true,
    order = 'drop reject sdrop alert log',
    rate_filter_memcap = 1048576
}

-- Define output formats
alert_fast = { }

-- Include rules
include = 'rules/local.rules'
'''
            self.snort_config.write_text(config_content)
            logger.info(f"Created Snort configuration file: {self.snort_config}")

    def _init_rules(self):
        """Initialize Snort rules file."""
        if not self.local_rules.exists():
            rules_content = '''# Local Snort rules

# Basic protocol detection
alert tcp any any -> any any (msg:"TCP Connection Detected"; sid:1000001; rev:1;)
alert udp any any -> any any (msg:"UDP Connection Detected"; sid:1000002; rev:1;)
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000003; rev:1;)

# Port scan detection
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; sid:1000004; rev:1;)
alert tcp any any -> any any (msg:"Stealth Scan Detected"; flags:SF,R; sid:1000005; rev:1;)

# Service detection
alert tcp any any -> any 22 (msg:"SSH Connection Attempt"; content:"SSH"; sid:1000006; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP Connection"; content:"HTTP/1.1"; sid:1000007; rev:1;)
alert tcp any any -> any 21 (msg:"FTP Connection Attempt"; content:"FTP"; sid:1000008; rev:1;)

# OS detection
alert tcp any any -> any any (msg:"OS Detection Attempt"; content:"TTL"; sid:1000009; rev:1;)
alert tcp any any -> any any (msg:"OS Detection Attempt"; content:"Window"; sid:1000010; rev:1;)

# Protocol probes
alert tcp any any -> any 80 (msg:"HTTP CONNECT Method"; content:"CONNECT"; sid:1000011; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP OPTIONS Method"; content:"OPTIONS"; sid:1000012; rev:1;)
'''
            self.local_rules.write_text(rules_content)
            logger.info(f"Created local rules file: {self.local_rules}")

    def setup_firewall(self):
        """Set up initial firewall rules"""
        try:
            # Clear existing rules
            subprocess.run(['sudo', 'iptables', '-F'], check=True)
            subprocess.run(['sudo', 'iptables', '-X'], check=True)
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F'], check=True)
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-X'], check=True)
            
            # Set default policies
            subprocess.run(['sudo', 'iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            
            logger.info("Firewall initialized with default rules")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error setting up firewall: {e}")

    def add_firewall_rule(self, ip):
        """Add a firewall rule to block suspicious IP"""
        if ip in self.blocked_ips:
            return

        try:
            # Add rule to block IP
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'], check=True)
            
            self.blocked_ips.add(ip)
            logger.info(f"Added firewall rules for IP: {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error adding firewall rule for IP {ip}: {e}")

    def remove_firewall_rule(self, ip):
        """Remove firewall rules for an IP"""
        if ip not in self.blocked_ips:
            return

        try:
            # Remove all rules for the IP
            subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            subprocess.run(['sudo', 'iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'], check=True)
            
            self.blocked_ips.remove(ip)
            logger.info(f"Removed firewall rules for IP: {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error removing firewall rule for IP {ip}: {e}")

    def process_alerts(self):
        """Process alerts and update firewall rules"""
        while True:
            try:
                alert = self.alert_queue.get()
                if alert is None:
                    break

                # Parse alert to get IP and type
                if '->' in alert:
                    parts = alert.split('->')
                    ip = parts[0].strip().split()[-1]
                    alert_type = None

                    # Determine alert type
                    if "Port Scan" in alert:
                        alert_type = "port_scan"
                    elif "Stealth Scan" in alert:
                        alert_type = "stealth_scan"
                    elif "Service Version Scan" in alert:
                        alert_type = "version_scan"
                    elif "OS Detection" in alert:
                        alert_type = "os_detection"
                    elif "Protocol Probe" in alert:
                        alert_type = "protocol_probe"
                    elif "TCP Connection" in alert:
                        alert_type = "tcp_connection"
                    elif "UDP Connection" in alert:
                        alert_type = "udp_connection"
                    elif "ICMP Packet" in alert:
                        alert_type = "icmp_packet"
                    elif "HTTP" in alert:
                        alert_type = "http_connection"
                    elif "FTP" in alert:
                        alert_type = "ftp_connection"
                    elif "SSH" in alert:
                        alert_type = "ssh_connection"

                    if alert_type:
                        self.add_firewall_rule(ip)
                        logger.info(f"Processing {alert_type} alert for IP: {ip}")
                        self.packet_count += 1

            except Exception as e:
                logger.error(f"Error processing alert: {e}")
            finally:
                self.alert_queue.task_done()

    def monitor_alerts(self):
        """Monitor alert_fast.txt for new alerts"""
        processed_alerts = set()

        while True:
            try:
                if self.alert_file.exists():
                    with open(self.alert_file, 'r') as f:
                        new_alerts = f.readlines()
                        for alert in new_alerts:
                            if alert not in processed_alerts:
                                processed_alerts.add(alert)
                                self.alert_queue.put(alert)
                                logger.info(f"New alert detected: {alert.strip()}")
                                self.packet_count += 1
            except Exception as e:
                logger.error(f"Error monitoring alerts: {e}")
            time.sleep(1)

    def start(self):
        """Start the IPS"""
        logger.info("Starting IPS...")
        
        # Start Snort in passive mode
        try:
            snort_cmd = ['sudo', 'snort', '-c', str(self.snort_config), '-i', 'wlo1', '--warn-all']
            logger.info("Starting Snort...")
            logger.info(f"Command: {' '.join(snort_cmd)}")
            
            # Start alert processing thread
            alert_processor = threading.Thread(target=self.process_alerts, daemon=True)
            alert_processor.start()
            
            # Start alert monitoring thread
            alert_monitor = threading.Thread(target=self.monitor_alerts, daemon=True)
            alert_monitor.start()
            
            # Run Snort
            subprocess.run(snort_cmd)
            
        except KeyboardInterrupt:
            logger.info("Stopping IPS...")
            self.alert_queue.put(None)
            alert_processor.join()
            alert_monitor.join()
        except Exception as e:
            logger.error(f"Error starting IPS: {e}")

def main():
    try:
        ips = IPS()
        ips.setup_firewall()
        ips.start()
        return 0
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())