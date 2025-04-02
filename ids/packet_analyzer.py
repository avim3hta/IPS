import subprocess
import threading
import logging
import json
import time
import os
import re
from typing import Callable, Dict, List, Optional
from pathlib import Path

class PacketAnalyzer:
    def __init__(self, snort_binary: str, config_path: str, capture_interface: str, output_dir: str):
        self.snort_binary = snort_binary
        self.config_path = config_path
        self.capture_interface = capture_interface
        self.output_dir = Path(output_dir)
        self.process = None
        self.running = False
        self.alert_callback = None
        self.logger = logging.getLogger(__name__)
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def start_capture(self, alert_callback: Optional[Callable[[Dict], None]] = None) -> bool:
        if self.running:
            self.logger.warning("Packet analyzer already running")
            return False
            
        self.alert_callback = alert_callback
        self.running = True
        
        try:
            # Start Snort in alert mode with unified2 output format
            cmd = [
                self.snort_binary,
                "-c", self.config_path,
                "-i", self.capture_interface,
                "-A", "console",
                "-l", str(self.output_dir),
                "--daq-dir=/usr/local/lib/daq",
                "--daq-var", "buffer_size=4096"
            ]
            
            self.logger.info(f"Starting Snort with command: {' '.join(cmd)}")
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            # Start alert monitoring thread
            alert_thread = threading.Thread(target=self._monitor_alerts)
            alert_thread.daemon = True
            alert_thread.start()
            
            # Start stderr monitoring thread
            stderr_thread = threading.Thread(target=self._monitor_stderr)
            stderr_thread.daemon = True
            stderr_thread.start()
            
            self.logger.info("Packet analyzer started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start packet analyzer: {e}")
            self.running = False
            return False
    
    def stop_capture(self) -> bool:
        if not self.running:
            return True
            
        try:
            self.running = False
            if self.process:
                self.process.terminate()
                self.process.wait(timeout=5)
                self.process = None
            self.logger.info("Packet analyzer stopped")
            return True
        except Exception as e:
            self.logger.error(f"Error stopping packet analyzer: {e}")
            if self.process:
                self.process.kill()
                self.process = None
            return False
    
    def _monitor_alerts(self):
        if not self.process:
            return
            
        try:
            for line in self.process.stdout:
                if not self.running:
                    break
                    
                line = line.strip()
                if "[**]" in line and not line.startswith("Commencing"):
                    alert_info = self._parse_alert(line)
                    if alert_info and self.alert_callback:
                        self.alert_callback(alert_info)
        except Exception as e:
            self.logger.error(f"Error in alert monitoring: {e}")
    
    def _monitor_stderr(self):
        if not self.process:
            return
            
        try:
            for line in self.process.stderr:
                if not self.running:
                    break
                line = line.strip()
                if line:
                    self.logger.warning(f"Snort stderr: {line}")
        except Exception as e:
            self.logger.error(f"Error in stderr monitoring: {e}")
    
    def _parse_alert(self, alert_line: str) -> Optional[Dict]:
        try:
            # Example format: [**] [1:1000:1] SNORT Alert [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.1.1:12345 -> 192.168.1.2:80
            parts = alert_line.split("[**]")
            if len(parts) < 2:
                return None
                
            # Extract SID
            sid_part = parts[1].strip()
            sid_match = re.search(r'\[(\d+):(\d+):(\d+)\]', sid_part)
            if not sid_match:
                return None
                
            gid = sid_match.group(1)
            sid = sid_match.group(2)
            rev = sid_match.group(3)
            
            # Extract message
            msg_part = sid_part.split("]", 1)[1].strip() if "]" in sid_part else ""
            
            # Extract classification and priority
            class_part = parts[2].strip() if len(parts) > 2 else ""
            class_match = re.search(r'\[Classification: (.*?)\]', class_part)
            classification = class_match.group(1) if class_match else ""
            
            prio_match = re.search(r'\[Priority: (\d+)\]', class_part)
            priority = int(prio_match.group(1)) if prio_match else 0
            
            # Extract protocol and IPs
            proto_ip_part = parts[-1].strip()
            proto_match = re.search(r'\{(.*?)\}', proto_ip_part)
            protocol = proto_match.group(1) if proto_match else ""
            
            ip_parts = proto_ip_part.split("}")[-1].strip()
            ip_match = re.search(r'(\S+) -> (\S+)', ip_parts)
            
            if ip_match:
                src = ip_match.group(1)
                dst = ip_match.group(2)
                
                src_parts = src.split(":")
                dst_parts = dst.split(":")
                
                src_ip = src_parts[0]
                src_port = int(src_parts[1]) if len(src_parts) > 1 else None
                
                dst_ip = dst_parts[0]
                dst_port = int(dst_parts[1]) if len(dst_parts) > 1 else None
            else:
                src_ip = dst_ip = None
                src_port = dst_port = None
            
            return {
                "timestamp": time.time(),
                "sid": sid,
                "gid": gid,
                "revision": rev,
                "message": msg_part,
                "classification": classification,
                "priority": priority,
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "raw_alert": alert_line
            }
        except Exception as e:
            self.logger.error(f"Error parsing alert: {e}")
            return None