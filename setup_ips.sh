#!/bin/bash

# Stop any existing Snort processes
sudo pkill snort

# Configure iptables for port mirroring
sudo iptables -t mangle -N SNORT 2>/dev/null || true
sudo iptables -t mangle -A PREROUTING -i wlo1 -j SNORT
sudo iptables -t mangle -A POSTROUTING -o wlo1 -j SNORT

# Set up firewall rules for IPS
sudo iptables -N IPS_BLOCK 2>/dev/null || true
sudo iptables -A INPUT -j IPS_BLOCK
sudo iptables -A FORWARD -j IPS_BLOCK
sudo iptables -A OUTPUT -j IPS_BLOCK

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Make IP forwarding permanent
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ip-forward.conf

# Configure network interface for promiscuous mode
sudo ip link set wlo1 promisc on

echo "IPS setup completed. You can now run the IPS system." 