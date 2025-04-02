import os
import sys
import time
import logging
import subprocess
import yaml
from datetime import datetime
from pathlib import Path

# Configure logging
logger = logging.getLogger('IPS')
logger.setLevel(logging.INFO)

# Create handlers
console_handler = logging.StreamHandler(sys.stdout)
file_handler = logging.FileHandler('ips.log')

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
        self.firewall_config = self.config_dir / 'firewall.yaml'
        
        # Create necessary directories
        self._create_directories()
        
        # Initialize Snort configuration
        self._init_snort_config()
        
        # Initialize rules
        self._init_rules()
        
        # Initialize firewall configuration
        self._init_firewall_config()

    def _create_directories(self):
        """Create necessary directories if they don't exist."""
        for directory in [self.config_dir, self.rules_dir, self.logs_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")

    def _init_snort_config(self):
        """Initialize Snort configuration file."""
        if not self.snort_config.exists():
            config_content = '''-- Snort 3.0 configuration

-- Setup the network addresses you are protecting
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Set up the rule paths
RULE_PATH = '../rules'

-- Configure DAQ for inline mode
daq = {
    module_dirs = {
        '/usr/local/lib/daq',
    },
    modules = {
        {
            name = 'pcap',
            mode = 'inline'
        }
    }
}

-- Configure output
alert_fast = {
    file = true,
    packet = false
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

-- Configure inline mode
inline = {
    mode = 'tap',
    interface = 'wlo1'
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
drop tcp any any -> any any (msg:"Blocked TCP Connection"; sid:1000001; rev:1;)
drop udp any any -> any any (msg:"Blocked UDP Connection"; sid:1000002; rev:1;)
drop icmp any any -> any any (msg:"Blocked ICMP Ping"; itype:8; sid:1000003; rev:1;)
'''
            self.local_rules.write_text(rules_content)
            logger.info(f"Created local rules file: {self.local_rules}")

    def _init_firewall_config(self):
        """Initialize firewall configuration file."""
        if not self.firewall_config.exists():
            config_content = {
                'rules': [
                    {
                        'id': 1,
                        'action': 'drop',
                        'protocol': 'tcp',
                        'source_ip': 'any',
                        'destination_ip': 'any',
                        'priority': 100,
                        'description': 'Block suspicious TCP connections',
                        'enabled': True
                    }
                ]
            }
            with open(self.firewall_config, 'w') as f:
                yaml.dump(config_content, f, default_flow_style=False)
            logger.info(f"Created firewall configuration file: {self.firewall_config}")

    def update_firewall_rules(self, alert):
        """Update firewall rules based on Snort alerts."""
        try:
            # Parse alert to extract relevant information
            # This is a simple example - you might want to enhance the parsing
            if "Blocked" in alert:
                logger.info(f"Updating firewall rules based on alert: {alert}")
                # Add the IP to the IPS_BLOCK chain
                subprocess.run(['sudo', 'iptables', '-A', 'IPS_BLOCK', '-j', 'DROP'], check=True)
        except Exception as e:
            logger.error(f"Error updating firewall rules: {e}")

    def start_snort(self):
        """Start Snort in inline mode."""
        try:
            # Stop any existing Snort processes
            subprocess.run(['sudo', 'pkill', 'snort'], check=False)
            
            # Start Snort
            cmd = [
                'sudo', 'snort',
                '-c', str(self.snort_config),
                '-i', 'wlo1',
                '--warn-all'
            ]
            
            logger.info("Starting Snort...")
            logger.info(f"Command: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1  # Line buffered
            )
            
            # Monitor Snort output
            while True:
                output = process.stdout.readline()
                if output:
                    logger.info(output.strip())
                error = process.stderr.readline()
                if error:
                    logger.error(error.strip())
                
                # Check if process has terminated
                if process.poll() is not None:
                    remaining_out, remaining_err = process.communicate()
                    if remaining_out:
                        logger.info(remaining_out.strip())
                    if remaining_err:
                        logger.error(remaining_err.strip())
                    break
                
                time.sleep(0.1)
            
            if process.returncode != 0:
                logger.error(f"Snort exited with code {process.returncode}")
                raise Exception(f"Snort failed to start (exit code {process.returncode})")
            
        except Exception as e:
            logger.error(f"Error starting Snort: {e}")
            raise

    def monitor_alerts(self):
        """Monitor Snort alerts in real-time and update firewall rules."""
        try:
            while True:
                if self.alert_file.exists():
                    with open(self.alert_file, 'r') as f:
                        alerts = f.readlines()
                        for alert in alerts:
                            logger.warning(f"Snort Alert: {alert.strip()}")
                            self.update_firewall_rules(alert.strip())
                    # Clear the alert file after reading
                    open(self.alert_file, 'w').close()
                time.sleep(1)
        except Exception as e:
            logger.error(f"Error monitoring alerts: {e}")
            raise

    def run(self):
        """Main method to run the IPS."""
        try:
            logger.info("Starting IPS...")
            self.start_snort()
            self.monitor_alerts()
        except KeyboardInterrupt:
            logger.info("Stopping IPS...")
            subprocess.run(['sudo', 'pkill', 'snort'], check=False)
        except Exception as e:
            logger.error(f"Error in IPS: {e}")
            raise

def main():
    try:
        ips = IPS()
        ips.run()
        return 0
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())