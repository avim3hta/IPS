import logging
from typing import Dict, List, Optional, Callable
import threading
import queue
import time

class AlertHandler:
    def __init__(self, alert_queue_size: int = 100):
        self.logger = logging.getLogger(__name__)
        self.alert_queue = queue.Queue(maxsize=alert_queue_size)
        self.running = False
        self.processing_thread = None
        self.alert_processors = []
        self.alert_filters = []
    
    def register_processor(self, processor: Callable[[Dict], None], priority: int = 0):
        self.alert_processors.append((processor, priority))
        self.alert_processors.sort(key=lambda x: -x[1])  # Sort by priority (highest first)
    
    def register_filter(self, filter_func: Callable[[Dict], bool]):
        self.alert_filters.append(filter_func)
    
    def process_alert(self, alert: Dict) -> None:
        try:
            # Check if alert passes all filters
            for filter_func in self.alert_filters:
                if not filter_func(alert):
                    return  # Alert filtered out
            
            # Queue alert for processing
            try:
                self.alert_queue.put(alert, block=False)
            except queue.Full:
                self.logger.warning("Alert queue full, dropping alert")
        except Exception as e:
            self.logger.error(f"Error processing alert: {e}")
    
    def start(self) -> bool:
        if self.running:
            return False
        
        self.running = True
        self.processing_thread = threading.Thread(target=self._processing_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        return True
    
    def stop(self) -> bool:
        if not self.running:
            return True
        
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        return True
    
    def _processing_loop(self) -> None:
        while self.running:
            try:
                # Get alert from queue with timeout to allow checking running flag
                try:
                    alert = self.alert_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                
                # Process the alert through all registered processors
                for processor, _ in self.alert_processors:
                    try:
                        processor(alert)
                    except Exception as e:
                        self.logger.error(f"Error in alert processor: {e}")
                
                self.alert_queue.task_done()
            except Exception as e:
                self.logger.error(f"Error in alert processing loop: {e}")
    
    def get_queue_size(self) -> int:
        return self.alert_queue.qsize()
    
    def is_running(self) -> bool:
        return self.running