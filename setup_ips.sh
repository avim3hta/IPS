#!/bin/bash

# IPS Setup Script
# This script configures your network interface for IPS mode with port mirroring

# Default interface (change as needed)
INTERFACE="wlo1"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root with sudo."
  exit 1
fi

# Check if interface was provided as argument
if [ "$1" != "" ]; then
  INTERFACE="$1"
fi

# Check if interface exists
if ! ip link show $INTERFACE &> /dev/null; then
  echo "Error: Interface $INTERFACE does not exist."
  echo "Available interfaces:"
  ip link show | grep -E "^[0-9]+" | cut -d: -f2 | sed 's/ //g'
  exit 1
fi

echo "=== IPS Setup ==="
echo "Setting up IPS on interface: $INTERFACE"

# Create required directories
mkdir -p config/rules logs

# Set interface to promiscuous mode
echo "Setting $INTERFACE to promiscuous mode..."
ip link set $INTERFACE promisc on

# Clear existing iptables rules
echo "Clearing existing iptables rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Setup port mirroring
echo "Setting up port mirroring..."
iptables -t mangle -A PREROUTING -i $INTERFACE -j NFQUEUE --queue-num 0
iptables -t mangle -A POSTROUTING -o $INTERFACE -j NFQUEUE --queue-num 0

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Create test alert
if [ ! -f "alert_fast.txt" ]; then
  echo "Creating test alert file..."
  touch alert_fast.txt
  chmod 666 alert_fast.txt
fi

echo "=== Setup Complete ==="
echo "IPS is now configured on $INTERFACE"
echo "Run 'sudo python3 main.py' to start the IPS"
echo "Run 'cd dashboard && python3 app.py' to start the dashboard" 