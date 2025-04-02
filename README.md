# IPS (Intrusion Prevention System)

A real-time Intrusion Prevention System that combines Snort for network traffic analysis with dynamic firewall rule management and a modern web dashboard for monitoring.

## Features

- Real-time network traffic monitoring and analysis
- Automatic blocking of suspicious traffic
- Dynamic firewall rule management
- Modern, real-time web dashboard
- Detailed alert logging and statistics
- IP-based threat tracking
- Top threats visualization

## Prerequisites

Before you begin, make sure you have the following installed:

1. Python 3.8 or higher
2. Snort 3.0 or higher
3. iptables
4. sudo privileges (for network interface configuration)

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
The system uses a custom Snort configuration optimized for IPS mode. The configuration is located at `config/snort.lua`. You can modify the rules in `rules/local.rules` to customize detection patterns.

## Usage

### 1. Start the IPS System
In one terminal:
```bash
python3 main.py
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

### Live Alerts
- Shows the 100 most recent alerts
- Each alert includes timestamp and message
- Auto-updates in real-time

### Recent IPs
- Lists recently detected IP addresses
- Updates automatically as new IPs are detected

### Top Threats
- Shows the 5 most common threat types
- Displays count for each threat type
- Updates in real-time

## Customization

### Adding Custom Rules
Edit `rules/local.rules` to add your own Snort rules. Example:
```snort
drop tcp any any -> any any (msg:"Custom Rule"; sid:1000004; rev:1;)
```

### Modifying Firewall Rules
The system automatically updates firewall rules based on alerts. You can modify the rule generation logic in `main.py` under the `update_firewall_rules` method.

### Dashboard Customization
The dashboard can be customized by modifying:
- `dashboard/templates/index.html` for layout changes
- `dashboard/app.py` for backend functionality
- CSS in the template for visual changes

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Make sure you're running setup scripts with sudo
   - Check file permissions for log files

2. **Network Interface Issues**
   - Verify your interface name in setup_ips.sh
   - Check if promiscuous mode is supported

3. **Dashboard Not Loading**
   - Ensure both main.py and dashboard are running
   - Check if port 5000 is available

4. **No Alerts Showing**
   - Verify Snort is running correctly
   - Check alert_fast.txt permissions
   - Ensure rules are properly configured

### Log Files
- `ips.log`: Main system log
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

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers. 