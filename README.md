# IPS (Intrusion Prevention System)

A real-time Intrusion Prevention System that combines Snort for network traffic analysis with dynamic firewall rule management and a modern web dashboard for monitoring.

## Features

- Real-time network traffic monitoring and analysis with packet tracking
- Automatic detection and blocking of suspicious traffic
- Dynamic firewall rule management based on detected threats
- Modern, real-time web dashboard with confidence indicators
- Detailed protocol statistics (TCP, UDP, ICMP, HTTP, etc.)
- Comprehensive scan detection (stealth, version, OS, aggressive scans)
- IP-based threat tracking and active scan monitoring
- Real-time alerts with confidence percentages
- Optimized performance with single-side port mirroring

## Prerequisites

Before you begin, make sure you have the following installed:

1. Python 3.8 or higher
2. Snort 3.0 or higher (tested with Snort 3.6.0)
3. iptables
4. sudo privileges (for network interface configuration)
5. tcpdump (for additional packet capture)

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/IPS.git
cd IPS
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Set Up Network Interface
Run the setup script to configure your network interface for IPS mode:
```bash
sudo ./setup_ips.sh
```

This script will:
- Configure iptables for port mirroring
- Set up firewall rules for IPS blocking
- Enable IP forwarding
- Configure the wireless interface in promiscuous mode

### 4. Configure Snort
The system uses a custom Snort configuration optimized for IPS mode. The configuration is located at `config/snort.lua`. You can modify the rules in `config/rules/local.rules` to customize detection patterns.

## Usage

### 1. Start the IPS System
```bash
sudo python3 main.py
```

### 2. Launch the Dashboard
In another terminal:
```bash
cd dashboard
python3 app.py
```

### 3. Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:5000
```

## Dashboard Features

### Real-time Statistics
- Total packets processed
- Number of blocked packets
- Block rate percentage
- Protocol distribution (TCP, UDP, ICMP, etc.)
- Service stats (HTTP, HTTPS, SSH, DNS, etc.)

### Scan Detection
- Displays confidence percentages for different scan types
- Stealth scan detection
- Version scan detection
- OS detection
- Aggressive scan detection
- Protocol probe detection

### Active Scans
- Real-time monitoring of active scanning attempts
- IP address tracking of scanner
- Scan type identification
- Duration tracking

### Recent Scan Alerts
- Timestamp of detection
- IP address of scanner
- Type of scan detected
- Confidence level indicator

### Live Alerts
- Shows the most recent alerts
- Each alert includes timestamp and message
- Auto-updates in real-time

### Recent IPs
- Lists recently detected IP addresses
- Updates automatically as new IPs are detected

### Top Threats
- Shows the most common threat types
- Displays count for each threat type
- Updates in real-time

## Customization

### Adding Custom Rules
Edit `config/rules/local.rules` to add your own Snort rules. Example:
```snort
alert tcp any any -> any any (msg:"Custom Rule"; sid:1000004; rev:1;)
```

### Modifying Firewall Rules
The system automatically updates firewall rules based on alerts. You can modify the rule generation logic in `main.py` under the `add_firewall_rule` method.

### Dashboard Customization
The dashboard can be customized by modifying:
- `dashboard/templates/index.html` for layout changes
- `dashboard/app.py` for backend functionality
- CSS in the template for visual changes

## System Architecture

### Network Monitoring
- Snort runs in tap mode to monitor traffic without duplication
- Packet tracking for comprehensive protocol statistics
- Firewall rules are dynamically added based on detected threats

### Alert Processing
- Alerts are processed in separate threads to prevent bottlenecks
- Queue-based approach ensures all alerts are handled efficiently
- Real-time notification through the dashboard

### Dashboard Communication
- WebSocket-based real-time updates
- RESTful API endpoints for data retrieval
- Automatic refresh of statistics

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Make sure you're running the main script with sudo
   - Check file permissions for log files and alert_fast.txt

2. **Network Interface Issues**
   - Verify your interface name in the main script (defaults to wlo1)
   - Check if promiscuous mode is supported
   - Run `ip link show` to confirm available interfaces

3. **Dashboard Not Loading**
   - Ensure both main.py and dashboard app.py are running
   - Check if port 5000 is available
   - Look for error messages in the terminal

4. **No Alerts Showing**
   - Verify Snort is running correctly (check main.py output)
   - Check alert_fast.txt permissions
   - Ensure rules are properly configured in local.rules

5. **Low Detection Rate**
   - Add more specific rules to local.rules
   - Adjust confidence thresholds in the dashboard app
   - Check network traffic with tcpdump to verify mirroring is working

### Log Files
- `logs/ips.log`: Main system log
- `alert_fast.txt`: Snort alerts
- `logs/`: Snort log directory

## Security Considerations

1. **Network Access**
   - The dashboard is accessible on all interfaces (0.0.0.0)
   - Consider adding authentication for production use

2. **Firewall Rules**
   - Monitor the number of rules to prevent performance issues
   - Regularly review and clean up old rules

3. **Log Management**
   - Implement log rotation for large deployments
   - Monitor disk space usage


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers. 
