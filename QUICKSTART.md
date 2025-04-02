# Quick Start Guide

Get your IPS system up and running in minutes!

## Quick Setup

1. **Install Dependencies**
   ```bash
   sudo dnf install snort python3-pip
   pip install -r requirements.txt
   ```

2. **Set Up Network**
   ```bash
   sudo ./setup_ips.sh
   ```

3. **Start the System**
   Open two terminal windows:

   Terminal 1 (IPS):
   ```bash
   python3 main.py
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

## What You'll See

- Real-time alerts from Snort
- Statistics about blocked traffic
- List of suspicious IPs
- Top threat types

## Basic Customization

1. **Add Rules**
   Edit `rules/local.rules`:
   ```snort
   drop tcp any any -> any any (msg:"Block Suspicious Traffic"; sid:1000004; rev:1;)
   ```

2. **Change Interface**
   Edit `setup_ips.sh` and change `wlo1` to your interface name

## Need Help?

- Check the full [README.md](README.md)
- Look at the logs in `ips.log`
- Check Snort logs in the `logs` directory

## Common Issues

1. **No Alerts?**
   - Make sure Snort is running
   - Check `alert_fast.txt` permissions
   - Verify your network interface

2. **Dashboard Not Loading?**
   - Check if both Python scripts are running
   - Make sure port 5000 is free
   - Try refreshing your browser

3. **Permission Errors?**
   - Use `sudo` for setup scripts
   - Check file permissions
   - Verify your user has sudo access

## Next Steps

1. Review the full documentation
2. Customize your rules
3. Set up log rotation
4. Add authentication to the dashboard
5. Monitor system performance 