import logging
from typing import Dict, List, Optional, Callable
import threading
import time
from enum import Enum

class ResponseAction(Enum):
    BLOCK_IP = "block_ip"
    BLOCK_PORT = "block_port"
    BLOCK_CONNECTION = "block_connection"
    RATE_LIMIT = "rate_limit"
    LOG_ONLY = "log_only"
    CUSTOM = "custom"

class ResponseRule:
    def __init__(self, name: str, condition: Callable[[Dict], bool], 
                 action: ResponseAction, parameters: Dict, priority: int = 0,
                 description: str = "", timeout: Optional[int] = None):
        self.name = name
        self.condition = condition
        self.action = action
        self.parameters = parameters
        self.priority = priority
        self.description = description
        self.timeout = timeout  # Seconds until response is automatically removed
        self.created_at = None  # Will be set when response is triggered
    
    def matches(self, alert: Dict) -> bool:
        try:
            return self.condition(alert)
        except Exception:
            return False
    
    def is_expired(self) -> bool:
        if not self.timeout or not self.created_at:
            return False
        return time.time() - self.created_at > self.timeout

class ResponseSystem:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.response_rules = []
        self.active_responses = []
        self.action_handlers = {}
        self.cleanup_thread = None
        self.running = False
    
    def register_action_handler(self, action: ResponseAction, 
                               handler: Callable[[Dict], bool]) -> None:
        self.action_handlers[action] = handler
    
    def add_response_rule(self, rule: ResponseRule) -> None:
        self.response_rules.append(rule)
        self.response_rules.sort(key=lambda x: -x.priority)  # Sort by priority
    
    def remove_response_rule(self, rule_name: str) -> bool:
        for i, rule in enumerate(self.response_rules):
            if rule.name == rule_name:
                self.response_rules.pop(i)
                return True
        return False
    
    def process_alert(self, alert: Dict) -> List[Dict]:
        responses = []
        
        for rule in self.response_rules:
            if rule.matches(alert):
                response = self._execute_response(rule, alert)
                if response:
                    responses.append(response)
        
        return responses
    
    def _execute_response(self, rule: ResponseRule, alert: Dict) -> Optional[Dict]:
        try:
            # Check if we have a handler for this action
            if rule.action not in self.action_handlers:
                self.logger.error(f"No handler registered for action {rule.action}")
                return None
            
            # Execute the action handler
            handler = self.action_handlers[rule.action]
            success = handler(rule.parameters)
            
            if not success:
                self.logger.error(f"Action handler failed for {rule.action}")
                return None
            
            # Create response record
            response = {
                "rule_name": rule.name,
                "action": rule.action.value,
                "parameters": rule.parameters,
                "alert_sid": alert.get("sid"),
                "alert_message": alert.get("message"),
                "timestamp": time.time(),
                "timeout": rule.timeout
            }
            
            # Add to active responses if it has a timeout
            if rule.timeout:
                rule.created_at = time.time()
                self.active_responses.append((rule, response))
            
            self.logger.info(f"Executed response {rule.name} for alert {alert.get('sid')}")
            return response
            
        except Exception as e:
            self.logger.error(f"Error executing response: {e}")
            return None
    
    def start(self) -> bool:
        if self.running:
            return False
        
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        return True
    
    def stop(self) -> bool:
        if not self.running:
            return True
        
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        return True
    
    def _cleanup_loop(self) -> None:
        while self.running:
            try:
                # Check for expired responses
                now = time.time()
                expired = []
                
                for i, (rule, response) in enumerate(self.active_responses):
                    if rule.is_expired():
                        expired.append((i, rule, response))
                
                # Remove expired responses (in reverse order to avoid index issues)
                for i, rule, response in sorted(expired, key=lambda x: -x[0]):
                    # Undo the action if possible
                    if rule.action in self.action_handlers:
                        self.logger.info(f"Removing expired response: {rule.name}")
                        # Here you would call a cleanup handler
                    
                    self.active_responses.pop(i)
            
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
            
            # Sleep a bit to avoid busy waiting
            time.sleep(5)
    
    def get_active_responses(self) -> List[Dict]:
        return [resp for _, resp in self.active_responses]