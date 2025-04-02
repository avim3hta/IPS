from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import time
import threading
import os
from datetime import datetime

class IPSState:
    def __init__(self):
        self.total_packets = 0
        self.blocked_packets = 0
        self.alerts = []
        self.recent_ips = set()
        self.top_threats = {}
        self.scan_stats = {
            'stealth_scan': {'count': 0, 'confidence': 0},
            'version_scan': {'count': 0, 'confidence': 0},
            'os_scan': {'count': 0, 'confidence': 0},
            'aggressive_scan': {'count': 0, 'confidence': 0},
            'protocol_probes': {'count': 0, 'confidence': 0}
        }
        self.protocol_stats = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'http': 0,
            'ssh': 0,
            'ftp': 0,
            'other': 0
        }
        self.scan_start_time = time.time()
        self.active_scans = {}  # Track active scans by IP
        self.scan_alerts = []   # Store recent scan alerts
        self.last_alert_check = 0

    def update_scan_confidence(self, scan_type, ip):
        self.scan_stats[scan_type]['count'] += 1
        total_scans = sum(stat['count'] for stat in self.scan_stats.values())
        
        # Calculate confidence based on number of detections
        if total_scans > 0:
            self.scan_stats[scan_type]['confidence'] = (self.scan_stats[scan_type]['count'] / total_scans) * 100

        # Track active scans
        if ip not in self.active_scans:
            self.active_scans[ip] = {
                'type': scan_type,
                'start_time': time.time(),
                'count': 1
            }
        else:
            self.active_scans[ip]['count'] += 1

        # Create alert message
        alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': ip,
            'type': scan_type,
            'confidence': self.scan_stats[scan_type]['confidence']
        }
        self.scan_alerts.append(alert)
        # Keep only last 50 alerts
        self.scan_alerts = self.scan_alerts[-50:]

    def update_protocol_stats(self, protocol):
        if protocol in self.protocol_stats:
            self.protocol_stats[protocol] += 1
        else:
            self.protocol_stats['other'] += 1
        self.total_packets += 1

    def update_threat_stats(self, threat):
        if threat in self.top_threats:
            self.top_threats[threat] += 1
        else:
            self.top_threats[threat] = 1

    def parse_alert(self, alert):
        # Update packet counts
        self.total_packets += 1
        
        # Extract IP if available
        ip = "unknown"
        if '->' in alert:
            parts = alert.split('->')
            ip = parts[0].strip().split()[-1]
            self.recent_ips.add(ip)
        
        # Extract threat type and count
        if 'msg:' in alert:
            threat = alert.split('msg:')[1].split(']')[0].strip('"')
            self.update_threat_stats(threat)
            
            # Update protocol stats
            if "TCP Connection" in threat:
                self.update_protocol_stats('tcp')
            elif "UDP Connection" in threat:
                self.update_protocol_stats('udp')
            elif "ICMP Packet" in threat:
                self.update_protocol_stats('icmp')
            elif "HTTP" in threat:
                self.update_protocol_stats('http')
            elif "SSH" in threat:
                self.update_protocol_stats('ssh')
            elif "FTP" in threat:
                self.update_protocol_stats('ftp')
            else:
                self.update_protocol_stats('other')
                
            # Update scan stats
            if "Port Scan" in threat or "Stealth Scan" in threat:
                self.update_scan_confidence('stealth_scan', ip)
            elif "Service Version Scan" in threat:
                self.update_scan_confidence('version_scan', ip)
            elif "OS Detection" in threat:
                self.update_scan_confidence('os_scan', ip)
            elif "Aggressive Scan" in threat:
                self.update_scan_confidence('aggressive_scan', ip)
            elif "Protocol Probe" in threat or "HTTP" in threat and "Method" in threat:
                self.update_scan_confidence('protocol_probes', ip)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app)
ips_state = IPSState()

def monitor_alerts():
    """Monitor alert_fast.txt for new alerts"""
    alert_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'alert_fast.txt')
    processed_alerts = set()
    
    while True:
        try:
            # Add regular packet counter updates even without alerts
            ips_state.total_packets += 1
            
            if os.path.exists(alert_file):
                # Get file size and modification time
                file_stat = os.stat(alert_file)
                file_size = file_stat.st_size
                mod_time = file_stat.st_mtime
                
                # Only process if file has changed
                if mod_time > ips_state.last_alert_check:
                    ips_state.last_alert_check = mod_time
                    
                    with open(alert_file, 'r') as f:
                        new_alerts = f.readlines()
                        for alert in new_alerts:
                            alert = alert.strip()
                            if alert and alert not in processed_alerts:
                                processed_alerts.add(alert)
                                
                                # Add alert to list
                                ips_state.alerts.append(alert)
                                if len(ips_state.alerts) > 100:
                                    ips_state.alerts.pop(0)
                                
                                # Parse and update stats
                                ips_state.parse_alert(alert)
                                ips_state.blocked_packets += 1
                                
                                # Emit real-time alert to dashboard
                                socketio.emit('alert', {'alert': alert})
        except Exception as e:
            print(f"Error monitoring alerts: {e}")
        
        # Emit stats update to dashboard
        socketio.emit('stats_update', get_stats_dict())
        time.sleep(0.5)

def get_stats_dict():
    # Convert top_threats dict to sorted list
    sorted_threats = sorted(ips_state.top_threats.items(), key=lambda x: x[1], reverse=True)[:5]
    
    stats = {
        'total_packets': ips_state.total_packets,
        'blocked_packets': ips_state.blocked_packets,
        'block_rate': (ips_state.blocked_packets / ips_state.total_packets * 100) if ips_state.total_packets > 0 else 0,
        'alerts': ips_state.alerts[-100:],  # Last 100 alerts
        'recent_ips': list(ips_state.recent_ips)[-10:],  # Last 10 IPs
        'top_threats': sorted_threats,  # Top 5 threats
        'scan_stats': ips_state.scan_stats,
        'protocol_stats': ips_state.protocol_stats,
        'scan_duration': int(time.time() - ips_state.scan_start_time),
        'active_scans': ips_state.active_scans,
        'scan_alerts': ips_state.scan_alerts
    }
    return stats

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(get_stats_dict())

if __name__ == '__main__':
    # Start alert monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor_alerts, daemon=True)
    monitor_thread.start()
    
    # Run the Flask app
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 