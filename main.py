import os
import sys
import time
import logging
import subprocess
import re
from datetime import datetime
from pathlib import Path
import threading
import queue
import socket
import struct
import fcntl

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

class NetworkPacketTracker:
    """Class to track network packets directly using libpcap"""
    def __init__(self, interface="wlo1"):
        self.interface = interface
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.ip_count = 0
        self.http_count = 0
        self.https_count = 0
        self.dns_count = 0
        self.ftp_count = 0
        self.ssh_count = 0
        self.other_count = 0
        self.running = False
        
    def start_capture(self):
        """Start packet capture using tcpdump"""
        self.running = True
        try:
            # Run tcpdump in a separate process and capture its output for parsing
            tcpdump_cmd = ["sudo", "tcpdump", "-i", self.interface, "-n", "-q", "-l"]
            self.tcpdump_process = subprocess.Popen(
                tcpdump_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Start a thread to read from tcpdump's output
            self.reader_thread = threading.Thread(target=self._read_packets, daemon=True)
            self.reader_thread.start()
            
            logger.info(f"Started packet capture on interface {self.interface}")
            return True
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            self.running = False
            return False
    
    def _read_packets(self):
        """Read and parse packets from tcpdump output"""
        while self.running:
            try:
                line = self.tcpdump_process.stdout.readline().strip()
                if not line:
                    continue
                    
                # Update packet counts based on the captured line
                self.ip_count += 1  # All packets are IP at this level
                
                # TCP
                if " tcp " in line.lower():
                    self.tcp_count += 1
                    
                    # HTTP
                    if " port 80 " in line or " port http " in line:
                        self.http_count += 1
                    # HTTPS
                    elif " port 443 " in line or " port https " in line:
                        self.https_count += 1
                    # SSH
                    elif " port 22 " in line or " port ssh " in line:
                        self.ssh_count += 1
                    # FTP
                    elif " port 21 " in line or " port ftp " in line:
                        self.ftp_count += 1
                # UDP
                elif " udp " in line.lower():
                    self.udp_count += 1
                    
                    # DNS
                    if " port 53 " in line or " port domain " in line:
                        self.dns_count += 1
                # ICMP
                elif " icmp " in line.lower():
                    self.icmp_count += 1
                else:
                    self.other_count += 1
                    
            except Exception as e:
                logger.error(f"Error reading packet: {e}")
                time.sleep(0.1)
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if hasattr(self, 'tcpdump_process'):
            try:
                self.tcpdump_process.terminate()
                self.tcpdump_process.wait(timeout=2)
            except:
                self.tcpdump_process.kill()
            
        if hasattr(self, 'reader_thread'):
            self.reader_thread.join(timeout=2)
            
        logger.info("Stopped packet capture")
    
    def get_stats(self):
        """Get current packet statistics"""
        return {
            'tcp': self.tcp_count,
            'udp': self.udp_count,
            'icmp': self.icmp_count,
            'http': self.http_count,
            'https': self.https_count,
            'dns': self.dns_count,
            'ssh': self.ssh_count,
            'ftp': self.ftp_count,
            'other': self.other_count,
            'total': self.ip_count
        }

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
        self.packet_tracker = NetworkPacketTracker("wlo1")
        
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

-- Define packet processing
process = {
    all_traffic = true,
    show_year = true
}

-- Configure output plugins
output = {
    file = true
}

-- Include rules
include = 'rules/local.rules'
'''
            self.snort_config.write_text(config_content)
            logger.info(f"Created Snort configuration file: {self.snort_config}")

    def _init_rules(self):
        """Initialize Snort rules file."""
        if not self.local_rules.exists():
            rules_content = '''# Local Snort rules

# Basic protocol detection - Log ALL traffic
alert ip any any -> any any (msg:"IP Packet Detected"; sid:1000001; rev:1;)
alert tcp any any -> any any (msg:"TCP Connection Detected"; sid:1000002; rev:1;)
alert udp any any -> any any (msg:"UDP Connection Detected"; sid:1000003; rev:1;)
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000004; rev:1;)

# Port scan detection
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; threshold:type both, track by_src, count 3, seconds 30; sid:1000005; rev:1;)
alert tcp any any -> any any (msg:"Stealth Scan Detected"; flags:SF,R; sid:1000006; rev:1;)

# Web traffic detection
alert tcp any any -> any 80 (msg:"HTTP Traffic"; content:"HTTP"; sid:1000007; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS Traffic"; content:"TLS"; sid:1000008; rev:1;)

# Common services
alert tcp any any -> any 22 (msg:"SSH Traffic"; content:"SSH"; sid:1000009; rev:1;)
alert tcp any any -> any 21 (msg:"FTP Traffic"; content:"FTP"; sid:1000010; rev:1;)
alert tcp any any -> any 53 (msg:"DNS (TCP) Traffic"; sid:1000011; rev:1;)
alert udp any any -> any 53 (msg:"DNS (UDP) Traffic"; sid:1000012; rev:1;)

# Common protocol detection
alert tcp any any -> any any (msg:"HTTP Protocol"; content:"GET"; sid:1000013; rev:1;)
alert tcp any any -> any any (msg:"HTTP Protocol"; content:"POST"; sid:1000014; rev:1;)
alert tcp any any -> any any (msg:"HTTP Protocol"; content:"HTTP/1.1"; sid:1000015; rev:1;)
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
            
            # Add basic rules
            # Allow loopback traffic
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
            # Allow established connections
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=True)
            # Enable logging
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-j', 'LOG', '--log-prefix', '"IPSBlocked: "'], check=True)
            
            logger.info("Firewall initialized with default rules")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error setting up firewall: {e}")

    def add_firewall_rule(self, ip):
        """Add a firewall rule to block suspicious IP"""
        if ip in self.blocked_ips or ip == "unknown" or ip == "127.0.0.1" or ip.startswith("192.168.") or ip.startswith("10."):
            return

        try:
            # Add rule to block IP
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'], check=True)
            
            self.blocked_ips.add(ip)
            logger.info(f"Added firewall rules for IP: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error adding firewall rule for IP {ip}: {e}")
            return False

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

    def check_firewall_rules(self):
        """Check and list current firewall rules"""
        try:
            result = subprocess.run(['sudo', 'iptables', '-L', '-n'], check=True, capture_output=True, text=True)
            logger.info(f"Current firewall rules:\n{result.stdout}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Error checking firewall rules: {e}")
            return None

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

                    if alert_type and ip:
                        # Try to add a firewall rule and log the result
                        if self.add_firewall_rule(ip):
                            logger.info(f"Successfully blocked {ip} for {alert_type}")
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
                            alert = alert.strip()
                            if alert and alert not in processed_alerts:
                                processed_alerts.add(alert)
                                self.alert_queue.put(alert)
                                logger.info(f"New alert detected: {alert}")
                                self.packet_count += 1
            except Exception as e:
                logger.error(f"Error monitoring alerts: {e}")
            
            # Periodically check and log firewall rules
            if self.packet_count % 100 == 0 and self.packet_count > 0:
                self.check_firewall_rules()
                
            time.sleep(1)

    def get_network_stats(self):
        """Get the current network statistics"""
        return self.packet_tracker.get_stats()

    def start(self):
        """Start the IPS"""
        logger.info("Starting IPS...")
        
        # Start packet tracker
        self.packet_tracker.start_capture()
        
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
            self.packet_tracker.stop_capture()
        except Exception as e:
            logger.error(f"Error starting IPS: {e}")
            self.packet_tracker.stop_capture()

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