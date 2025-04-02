from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import json
import os
from datetime import datetime
import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app)

# Global variables to store statistics
stats = {
    'total_packets': 0,
    'blocked_packets': 0,
    'alerts': [],
    'recent_ips': set(),
    'top_threats': {}
}

def monitor_alerts():
    """Monitor alert_fast.txt for new alerts"""
    alert_file = 'alert_fast.txt'
    last_position = 0
    
    while True:
        try:
            if os.path.exists(alert_file):
                with open(alert_file, 'r') as f:
                    f.seek(last_position)
                    new_alerts = f.readlines()
                    if new_alerts:
                        for alert in new_alerts:
                            alert = alert.strip()
                            stats['alerts'].append({
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'message': alert
                            })
                            # Keep only last 100 alerts
                            if len(stats['alerts']) > 100:
                                stats['alerts'].pop(0)
                            
                            # Update statistics
                            stats['total_packets'] += 1
                            if 'Blocked' in alert:
                                stats['blocked_packets'] += 1
                            
                            # Extract IP addresses
                            if 'src' in alert.lower():
                                try:
                                    ip = alert.split('src')[1].split()[0]
                                    stats['recent_ips'].add(ip)
                                except:
                                    pass
                            
                            # Update top threats
                            threat_type = alert.split('msg:')[1].split(';')[0].strip('"') if 'msg:' in alert else 'Unknown'
                            stats['top_threats'][threat_type] = stats['top_threats'].get(threat_type, 0) + 1
                            
                            # Emit update to all connected clients
                            socketio.emit('alert_update', {
                                'stats': stats,
                                'new_alert': {
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'message': alert
                                }
                            })
                        
                        last_position = f.tell()
                
                # Clear the alert file after reading
                open(alert_file, 'w').close()
            
            time.sleep(1)
        except Exception as e:
            print(f"Error monitoring alerts: {e}")
            time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(stats)

if __name__ == '__main__':
    # Start alert monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor_alerts, daemon=True)
    monitor_thread.start()
    
    # Run the Flask application
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 