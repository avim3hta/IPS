# Quick Start Guide

Get your IPS system up and running in minutes!

## Quick Setup

1. **Install Dependencies**
   ```bash
   # For Fedora/RedHat:
   sudo dnf install snort python3-pip tcpdump
   
   # For Ubuntu/Debian:
   sudo apt update
   sudo apt install snort python3-pip tcpdump
   
   # Install Python dependencies
   pip install flask flask-socketio requests
   ```

2. **Set Up Network Interface**
   
   Check your network interface name:
   ```bash
   ip link show
   ```
   
   Make sure your interface (e.g., wlo1) is in promiscuous mode:
   ```bash
   sudo ip link set wlo1 promisc on
   ```

3. **Start the System**
   
   Terminal 1 (IPS):
   ```bash
   sudo python3 main.py
   ```
   
   Terminal 2 (Dashboard):
   ```bash
   cd dashboard
   python3 app.py
   ```

4. **View Dashboard**
   
   Open your browser and go to:
   ```
   http://localhost:5000
   ```

## Features at a Glance

- **Real-time Monitoring**: See network traffic as it happens
- **Automatic Threat Detection**: Identifies port scans, probes, and attacks
- **Protocol Statistics**: Track TCP, UDP, ICMP, HTTP, SSH and more
- **Scan Confidence**: See how confident the system is about detected scans
- **Active Scanner Tracking**: Monitor who's scanning your network in real-time

## Basic Rule Customization

Edit `config/rules/local.rules` to customize detection:

```snort
# Block suspicious SSH traffic
alert tcp any any -> any 22 (msg:"Suspicious SSH Connection Attempt"; threshold: type limit, track by_src, count 5, seconds 60; sid:1000501; rev:1;)

# Detect port scanning
alert tcp any any -> any any (flags:S; msg:"Stealth Scan Detected"; sid:1000401; rev:1;)

# Detect HTTP attacks
alert tcp any any -> any 80 (content:"GET /admin"; msg:"Admin Page Access Attempt"; sid:1000601; rev:1;)
```

## Dashboard Overview

- **Statistics Panel**: Shows packet counts and protocol distribution
- **Scan Detection**: Displays confidence levels for different scan types
- **Active Scans**: Shows current ongoing scanning activity
- **Recent Alerts**: Lists the latest detected threats
- **Top Threats**: Summarizes most common attack types

## Troubleshooting Tips

1. **No Traffic Shown?**
   - Check if your interface is in promiscuous mode
   - Verify Snort is running (check main.py output)
   - Try generating some test traffic: `ping google.com`

2. **Dashboard Not Loading?**
   - Make sure both Python scripts are running
   - Check for errors in the terminal output
   - Verify port 5000 is not in use: `sudo lsof -i:5000`

3. **Permission Errors?**
   - Make sure to run the main.py with sudo
   - Check file permissions for log files
   - Run the dashboard app.py as a regular user (not sudo)

## Quick Reset

If you need to reset the statistics:
1. Click the "Reset Stats" button on the dashboard
2. Or restart both applications

## Next Steps

1. Read the full [README.md](README.md) for detailed documentation
2. Customize the rules in `config/rules/local.rules`
3. Adjust Snort configuration in `config/snort.lua`
4. Learn more about [Snort rules](https://docs.snort.org/rules/) 