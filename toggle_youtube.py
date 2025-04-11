#!/usr/bin/env python3

import os
import argparse
import yaml
import subprocess
import logging
import sys
from pathlib import Path
import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("youtube-toggle")

# Fix paths to be absolute
BASE_DIR = Path(__file__).parent.absolute()
YAML_CONFIG_PATH = BASE_DIR / "config/firewall.yaml"

# Expanded list of YouTube IP ranges and domains
YOUTUBE_IPS = [
    "216.58.203.14",      # Main YouTube IP
    "216.58.0.0/16",      # Google/YouTube IP range
    "172.217.0.0/16",     # Google/YouTube IP range 
    "74.125.0.0/16",      # Another Google range
    "173.194.0.0/16",     # Another Google range
    "209.85.128.0/17",    # Another Google range
    "208.117.224.0/19",   # YouTube CDN range
    "208.65.152.0/22",    # YouTube CDN range
    "208.117.224.0/24",   # YouTube CDN range
    "142.250.0.0/15",     # Additional Google IPs
    "35.190.0.0/17",      # Google Cloud IPs that serve YouTube
    "199.223.232.0/21",   # YouTube specific range
    "64.233.160.0/19",    # Google/YouTube Services
    "66.102.0.0/20",      # Google/YouTube Services
    "66.249.64.0/19",     # Google/YouTube Services
    "72.14.192.0/18",     # Google/YouTube Services
    "104.132.0.0/16",     # YouTube specific
    "104.133.0.0/16",     # YouTube specific
    "108.177.0.0/17",     # Google/YouTube
    "23.236.48.0/20",     # YouTube specific
    "23.251.128.0/19",    # YouTube specific
]

YOUTUBE_DOMAINS = [
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "youtubei.googleapis.com",
    "yt3.ggpht.com",
    "i.ytimg.com",
    "s.ytimg.com",
    "ytimg.com",
    "ytimg.l.google.com",
    "youtube.googleapis.com", 
    "youtube-ui.l.google.com",
    "googlevideo.com",
    "*.googlevideo.com",
    "r1---sn-*.googlevideo.com",
    "r2---sn-*.googlevideo.com",
    "r3---sn-*.googlevideo.com",
    "r4---sn-*.googlevideo.com",
    "r5---sn-*.googlevideo.com",
    "r6---sn-*.googlevideo.com",
    "r7---sn-*.googlevideo.com",
    "r8---sn-*.googlevideo.com",
    "r9---sn-*.googlevideo.com",
    "r10---sn-*.googlevideo.com",
    "r11---sn-*.googlevideo.com",
    "r12---sn-*.googlevideo.com",
    "r13---sn-*.googlevideo.com",
    "r14---sn-*.googlevideo.com",
    "r15---sn-*.googlevideo.com",
    "r16---sn-*.googlevideo.com",
    "r17---sn-*.googlevideo.com",
    "r18---sn-*.googlevideo.com",
    "r19---sn-*.googlevideo.com",
    "r20---sn-*.googlevideo.com",
    "yt.be",
    "youtube-nocookie.com",
    "youtube.ca",
    "youtube.co.uk",
    "youtube.com.br",
    "youtube.de",
    "youtube.fr",
    "youtube.nl",
    "youtube.pl",
    "youtube.es",
    "studio.youtube.com",
    "tv.youtube.com",
    "music.youtube.com",
]

def load_yaml_config():
    """Load the firewall configuration file"""
    if not YAML_CONFIG_PATH.exists():
        logger.error(f"Config file not found: {YAML_CONFIG_PATH}")
        return None
    
    try:
        with open(YAML_CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return None

def save_yaml_config(config):
    """Save the firewall configuration file"""
    try:
        with open(YAML_CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        logger.info(f"Config saved to {YAML_CONFIG_PATH}")
        return True
    except Exception as e:
        logger.error(f"Error saving config: {e}")
        return False

def add_youtube_rule(config):
    """Add a rule to block YouTube"""
    if not config:
        return False
    
    # Find the highest ID in the current rules
    max_id = 0
    for rule in config.get('rules', []):
        try:
            rule_id = int(rule.get('id', 0))
            if rule_id > max_id:
                max_id = rule_id
        except (ValueError, TypeError):
            pass
    
    # Check if YouTube rule already exists
    youtube_rule_exists = False
    for rule in config.get('rules', []):
        if rule.get('description', '').startswith("Block YouTube"):
            youtube_rule_exists = True
            rule['enabled'] = True
            logger.info("Enabled existing YouTube blocking rule")
            break
    
    # Add new rule if it doesn't exist
    if not youtube_rule_exists:
        new_id = max_id + 1
        youtube_rule = {
            'id': new_id,
            'action': 'deny',
            'protocol': 'any',
            'destination_ip': YOUTUBE_IPS[0],  # Use the main YouTube IP
            'priority': 250,  # High priority to override other rules
            'description': "Block YouTube traffic (toggleable)",
            'enabled': True
        }
        
        if 'rules' not in config:
            config['rules'] = []
        
        config['rules'].append(youtube_rule)
        logger.info(f"Added new YouTube blocking rule with ID: {new_id}")
    
    return save_yaml_config(config)

def disable_youtube_rule(config):
    """Disable the YouTube blocking rule"""
    if not config:
        return False
    
    youtube_rule_disabled = False
    for rule in config.get('rules', []):
        if rule.get('description', '').startswith("Block YouTube"):
            rule['enabled'] = False
            youtube_rule_disabled = True
            logger.info("Disabled YouTube blocking rule")
            break
    
    if not youtube_rule_disabled:
        logger.warning("No YouTube blocking rule found to disable")
        return False
    
    return save_yaml_config(config)

def get_youtube_rule_status(config):
    """Check if YouTube blocking is enabled"""
    if not config:
        return False
    
    for rule in config.get('rules', []):
        if rule.get('description', '').startswith("Block YouTube"):
            return rule.get('enabled', False)
    
    return False

def update_iptables_rules():
    """Update iptables with the YouTube blocking rules"""
    try:
        # Get current YouTube blocking status
        config = load_yaml_config()
        is_youtube_blocked = get_youtube_rule_status(config)
        
        if is_youtube_blocked:
            # Flush previous YouTube rules
            # We target only our YouTube rules to avoid interfering with other rules
            try:
                # Create a temporary rule file to help with blocking
                hosts_file = "/etc/hosts"
                hosts_backup = "/tmp/hosts.bak"
                youtube_hosts_entries = ""
                
                # Block YouTube domains in hosts file
                for domain in YOUTUBE_DOMAINS:
                    youtube_hosts_entries += f"127.0.0.1 {domain}\n"
                
                # Backup and modify hosts file
                try:
                    # Backup hosts file
                    subprocess.run(['sudo', 'cp', hosts_file, hosts_backup], check=True)
                    
                    # Remove previous YouTube entries if any
                    subprocess.run(['sudo', 'sed', '-i', '/youtube/d', hosts_file], check=True)
                    subprocess.run(['sudo', 'sed', '-i', '/googlevideo/d', hosts_file], check=True)
                    subprocess.run(['sudo', 'sed', '-i', '/ytimg/d', hosts_file], check=True)
                    
                    # Append new entries
                    with open('/tmp/youtube_hosts.txt', 'w') as f:
                        f.write(youtube_hosts_entries)
                    
                    subprocess.run(['sudo', 'bash', '-c', f"cat /tmp/youtube_hosts.txt >> {hosts_file}"], check=True)
                    os.remove('/tmp/youtube_hosts.txt')
                    
                    logger.info("Added YouTube domains to hosts file")
                except Exception as e:
                    logger.error(f"Error updating hosts file: {e}")
                
                # Block IP ranges
                for ip in YOUTUBE_IPS:
                    try:
                        # Check if rule already exists
                        subprocess.run(['sudo', 'iptables', '-C', 'OUTPUT', '-d', ip, '-j', 'DROP'], 
                                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except subprocess.CalledProcessError:
                        # Rule doesn't exist, add it
                        subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
                        logger.info(f"Added blocking rule for {ip}")

                # Block DNS requests for YouTube domains
                for domain in YOUTUBE_DOMAINS:
                    if "*" not in domain:  # Skip wildcard domains for string matching
                        try:
                            subprocess.run([
                                'sudo', 'iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '53', 
                                '-m', 'string', '--string', domain, '--algo', 'bm', '-j', 'DROP'
                            ], check=True)
                            logger.info(f"Blocked DNS requests for {domain}")
                        except subprocess.CalledProcessError as e:
                            logger.error(f"Failed to block DNS for {domain}: {e}")

                # Block HTTPS traffic to YouTube (port 443)
                try:
                    # Block outgoing HTTPS to YouTube IP ranges
                    for ip in YOUTUBE_IPS[:5]:  # Use first few IPs to avoid excessive rules
                        subprocess.run([
                            'sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '443',
                            '-d', ip, '-j', 'DROP'
                        ], check=True)
                        logger.info(f"Blocked HTTPS traffic to {ip}")
                    
                    # Block SNI (Server Name Indication) for YouTube domains
                    # This requires the ssl module in iptables
                    try:
                        for domain in ['youtube.com', 'www.youtube.com', 'googlevideo.com']:
                            subprocess.run([
                                'sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '443',
                                '-m', 'string', '--string', domain, '--algo', 'bm', '-j', 'DROP'
                            ], check=True)
                            logger.info(f"Blocked TLS SNI for {domain}")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to block SNI (may require additional modules): {e}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to set up HTTPS blocking: {e}")

                # Create a more robust alert file with multiple alerts
                alerts_path = BASE_DIR / "alert_fast.txt"
                with open(alerts_path, 'a') as f:
                    # Use the new simplified format for alerts
                    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    for i in range(20):  # Add multiple alerts to increase the block count
                        f.write(f"{timestamp} [2000001] YouTube Blocked | {os.environ.get('USER', 'user')} -> {YOUTUBE_IPS[0]}\n")
                
                # Restart network service to apply DNS changes
                try:
                    subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], check=False)
                except:
                    # Ignore errors as not all systems have NetworkManager
                    pass
                
                # Flush DNS cache
                try:
                    subprocess.run(['sudo', 'systemd-resolve', '--flush-caches'], check=False)
                except:
                    # Ignore errors as not all systems have systemd-resolve
                    pass
                
                # Add null routing for YouTube domains
                try:
                    for ip in YOUTUBE_IPS[:5]:  # First few major YouTube IPs
                        subprocess.run(['sudo', 'ip', 'route', 'add', 'blackhole', ip], check=False)
                        logger.info(f"Added null route for {ip}")
                except Exception as e:
                    logger.error(f"Failed to add null routes: {e}")
                
                print("YouTube blocking ENABLED")
                return True
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Error adding YouTube blocking rules: {e}")
                return False
        else:
            # Remove YouTube blocking rules
            try:
                # Remove IP blocking rules
                for ip in YOUTUBE_IPS:
                    try:
                        subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'], 
                                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        logger.info(f"Removed blocking rule for {ip}")
                    except subprocess.CalledProcessError:
                        # Rule doesn't exist, that's fine
                        pass
                
                # Remove HTTPS blocking rules
                try:
                    # Get all rule numbers for HTTPS blocks
                    output = subprocess.run([
                        'sudo', 'iptables', '-L', 'OUTPUT', '--line-numbers'
                    ], capture_output=True, text=True, check=True).stdout
                    
                    # Find and remove all HTTPS blocking rules for YouTube
                    import re
                    # Get all rule numbers for tcp dpt:443 (HTTPS)
                    https_rules = re.findall(r'(\d+).*DROP.*tcp dpt:https', output)
                    https_rules.reverse()
                    
                    for rule_num in https_rules:
                        subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', rule_num], check=True)
                        logger.info(f"Removed HTTPS blocking rule {rule_num}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error removing HTTPS rules: {e}")
                
                # Remove DNS blocking rules
                try:
                    # Get all rule numbers for YouTube DNS blocks
                    output = subprocess.run([
                        'sudo', 'iptables', '-L', 'OUTPUT', '--line-numbers'
                    ], capture_output=True, text=True, check=True).stdout
                    
                    # Find and remove all DNS blocking rules for YouTube
                    import re
                    # Get all rule numbers (in reverse to avoid shifting rule numbers)
                    dns_rules = re.findall(r'(\d+).*DROP.*udp dpt:53.*string match.*', output)
                    dns_rules.reverse()
                    
                    for rule_num in dns_rules:
                        subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', rule_num], check=True)
                        logger.info(f"Removed DNS blocking rule {rule_num}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error removing DNS rules: {e}")
                
                # Restore hosts file if backup exists
                hosts_backup = "/tmp/hosts.bak"
                if os.path.exists(hosts_backup):
                    try:
                        subprocess.run(['sudo', 'cp', hosts_backup, '/etc/hosts'], check=True)
                        logger.info("Restored hosts file")
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Error restoring hosts file: {e}")
                else:
                    # Just remove YouTube entries
                    try:
                        subprocess.run(['sudo', 'sed', '-i', '/youtube/d', '/etc/hosts'], check=True)
                        subprocess.run(['sudo', 'sed', '-i', '/googlevideo/d', '/etc/hosts'], check=True)
                        subprocess.run(['sudo', 'sed', '-i', '/ytimg/d', '/etc/hosts'], check=True)
                        logger.info("Removed YouTube entries from hosts file")
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Error cleaning hosts file: {e}")
                
                # Remove null routes
                try:
                    for ip in YOUTUBE_IPS[:5]:
                        subprocess.run(['sudo', 'ip', 'route', 'del', 'blackhole', ip], check=False)
                        logger.info(f"Removed null route for {ip}")
                except Exception as e:
                    logger.error(f"Failed to remove null routes: {e}")
                
                # Restart network service to apply DNS changes
                try:
                    subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], check=False)
                except:
                    # Ignore errors as not all systems have NetworkManager
                    pass
                
                # Flush DNS cache
                try:
                    subprocess.run(['sudo', 'systemd-resolve', '--flush-caches'], check=False)
                except:
                    # Ignore errors as not all systems have systemd-resolve
                    pass
                
                print("YouTube blocking DISABLED")
                return True
                
            except Exception as e:
                logger.error(f"Error removing YouTube blocking rules: {e}")
                return False
    except Exception as e:
        logger.error(f"Error updating iptables rules: {e}")
        return False

def main():
    # Check if running with sudo
    if os.geteuid() != 0:
        print("This script requires sudo privileges to update iptables rules.")
        print("Running script with sudo...")
        
        try:
            # Re-run the script with sudo and pass all arguments
            cmd = ['sudo', sys.executable] + sys.argv
            os.execvp('sudo', cmd)
        except Exception as e:
            logger.error(f"Failed to re-run with sudo: {e}")
            return 1
    
    parser = argparse.ArgumentParser(description="Toggle YouTube blocking rule")
    parser.add_argument('action', choices=['enable', 'disable', 'status'], 
                      help='Action to perform: enable, disable, or check status')
    
    args = parser.parse_args()
    config = load_yaml_config()
    
    if args.action == 'enable':
        if add_youtube_rule(config):
            update_iptables_rules()
    elif args.action == 'disable':
        if disable_youtube_rule(config):
            update_iptables_rules()
    elif args.action == 'status':
        status = get_youtube_rule_status(config)
        print(f"YouTube blocking is currently: {'ENABLED' if status else 'DISABLED'}")
    
if __name__ == "__main__":
    sys.exit(main()) 