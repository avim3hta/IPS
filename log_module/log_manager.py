import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

class LogManager:
    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
        # Create separate log files
        self.alert_log_path = self.log_dir / "alerts.log"
        self.firewall_log_path = self.log_dir / "firewall.log"
        self.system_log_path = self.log_dir / "system.log"
    
    def log_alert(self, alert: Dict[str, Any]) -> bool:
        try:
            timestamp = datetime.fromtimestamp(
                alert.get("timestamp", datetime.now().timestamp())
            ).strftime("%Y-%m-%d %H:%M:%S")
            
            alert_entry = {
                "timestamp": timestamp,
                "sid": alert.get("sid", "unknown"),
                "message": alert.get("message", ""),
                "priority": alert.get("priority", 0),
                "src_ip": alert.get("src_ip", ""),
                "dst_ip": alert.get("dst_ip", ""),
                "protocol": alert.get("protocol", "")
            }
            
            with open(self.alert_log_path, "a") as f:
                f.write(json.dumps(alert_entry) + "\n")
            
            return True
        except Exception as e:
            self.logger.error(f"Error logging alert: {e}")
            return False
    
    def log_firewall_action(self, action: Dict[str, Any]) -> bool:
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            action_entry = {
                "timestamp": timestamp,
                "rule_id": action.get("rule_id", ""),
                "action": action.get("action", ""),
                "src_ip": action.get("src_ip", ""),
                "dst_ip": action.get("dst_ip", ""),
                "protocol": action.get("protocol", ""),
                "reason": action.get("reason", "")
            }
            
            with open(self.firewall_log_path, "a") as f:
                f.write(json.dumps(action_entry) + "\n")
            
            return True
        except Exception as e:
            self.logger.error(f"Error logging firewall action: {e}")
            return False
    
    def log_system_event(self, event_type: str, details: Dict[str, Any]) -> bool:
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            event_entry = {
                "timestamp": timestamp,
                "type": event_type,
                "details": details
            }
            
            with open(self.system_log_path, "a") as f:
                f.write(json.dumps(event_entry) + "\n")
            
            return True
        except Exception as e:
            self.logger.error(f"Error logging system event: {e}")
            return False
    
    def get_recent_alerts(self, count: int = 100) -> List[Dict[str, Any]]:
        try:
            if not self.alert_log_path.exists():
                return []
                
            alerts = []
            with open(self.alert_log_path, "r") as f:
                lines = f.readlines()
                for line in lines[-count:]:
                    alerts.append(json.loads(line.strip()))
            return alerts
        except Exception as e:
            self.logger.error(f"Error getting recent alerts: {e}")
            return []
    
    def get_recent_firewall_actions(self, count: int = 100) -> List[Dict[str, Any]]:
        try:
            if not self.firewall_log_path.exists():
                return []
                
            actions = []
            with open(self.firewall_log_path, "r") as f:
                lines = f.readlines()
                for line in lines[-count:]:
                    actions.append(json.loads(line.strip()))
            return actions
        except Exception as e:
            self.logger.error(f"Error getting recent firewall actions: {e}")
            return []
    
    def get_system_events(self, event_type: Optional[str] = None, count: int = 100) -> List[Dict[str, Any]]:
        try:
            if not self.system_log_path.exists():
                return []
                
            events = []
            with open(self.system_log_path, "r") as f:
                lines = f.readlines()
                for line in lines[-count:]:
                    event = json.loads(line.strip())
                    if event_type is None or event.get("type") == event_type:
                        events.append(event)
            return events
        except Exception as e:
            self.logger.error(f"Error getting system events: {e}")
            return []
    
    def clear_logs(self) -> bool:
        try:
            if self.alert_log_path.exists():
                self.alert_log_path.unlink()
            if self.firewall_log_path.exists():
                self.firewall_log_path.unlink()
            if self.system_log_path.exists():
                self.system_log_path.unlink()
            return True
        except Exception as e:
            self.logger.error(f"Error clearing logs: {e}")
            return False
    
    def archive_logs(self, archive_dir: str) -> bool:
        try:
            archive_path = Path(archive_dir)
            archive_path.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if self.alert_log_path.exists():
                dest = archive_path / f"alerts_{timestamp}.log"
                with open(self.alert_log_path, "r") as src_file, open(dest, "w") as dest_file:
                    dest_file.write(src_file.read())
                
            if self.firewall_log_path.exists():
                dest = archive_path / f"firewall_{timestamp}.log"
                with open(self.firewall_log_path, "r") as src_file, open(dest, "w") as dest_file:
                    dest_file.write(src_file.read())
                
            if self.system_log_path.exists():
                dest = archive_path / f"system_{timestamp}.log"
                with open(self.system_log_path, "r") as src_file, open(dest, "w") as dest_file:
                    dest_file.write(src_file.read())
            
            return True
        except Exception as e:
            self.logger.error(f"Error archiving logs: {e}")
            return False
    
    def rotate_logs(self, max_size_mb: int = 10) -> bool:
        try:
            max_bytes = max_size_mb * 1024 * 1024
            
            for log_path in [self.alert_log_path, self.firewall_log_path, self.system_log_path]:
                if log_path.exists() and log_path.stat().st_size > max_bytes:
                    # Create rotation filename with timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    rotated_path = self.log_dir / f"{log_path.stem}_{timestamp}{log_path.suffix}"
                    
                    # Rename current log to rotated filename
                    log_path.rename(rotated_path)
                    
                    # Touch new empty log file
                    log_path.touch()
                    
                    self.logger.info(f"Rotated log file {log_path} to {rotated_path}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error rotating logs: {e}")
            return False