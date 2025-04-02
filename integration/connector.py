import logging
from typing import Dict, Any, Optional
from firewall.firewall_rules import RuleManager, Rule, Action, Protocol
from ids.packet_analyzer import PacketAnalyzer
from integration.alert_handler import AlertHandler
from integration.response_system import ResponseSystem, ResponseAction, ResponseRule

class IDSFirewallConnector:
    def __init__(self, rule_manager: RuleManager, 
                alert_handler: AlertHandler,
                response_system: ResponseSystem):
        self.rule_manager = rule_manager
        self.alert_handler = alert_handler
        self.response_system = response_system
        self.logger = logging.getLogger(__name__)
        
    def setup(self):
        # Register with the alert handler
        self.alert_handler.register_processor(self._process_alert, priority=100)
        
        # Register action handlers with response system
        self.response_system.register_action_handler(
            ResponseAction.BLOCK_IP, self._handle_block_ip
        )
        self.response_system.register_action_handler(
            ResponseAction.BLOCK_PORT, self._handle_block_port
        )
        self.response_system.register_action_handler(
            ResponseAction.BLOCK_CONNECTION, self._handle_block_connection
        )
        
        # Add some default response rules
        self._add_default_response_rules()
        
        self.logger.info("IDS-Firewall connector setup complete")
    
    def _process_alert(self, alert: Dict[str, Any]):
        # Let the response system handle the alert
        responses = self.response_system.process_alert(alert)
        
        for response in responses:
            self.logger.info(f"Response triggered: {response['rule_name']} - {response['action']}")
    
    def _handle_block_ip(self, params: Dict[str, Any]) -> bool:
        try:
            ip = params.get('ip')
            if not ip:
                return False
                
            # Create a firewall rule to block the IP
            rule = Rule(
                action=Action.DENY,
                source_ip=ip,
                description=f"Auto-block IP from IDS alert: {params.get('reason', 'Unknown')}",
                priority=200  # High priority
            )
            
            self.rule_manager.add_rule(rule)
            return True
        except Exception as e:
            self.logger.error(f"Error handling block_ip action: {e}")
            return False
    
    def _handle_block_port(self, params: Dict[str, Any]) -> bool:
        try:
            port = params.get('port')
            protocol_str = params.get('protocol', 'any')
            
            if not port:
                return False
                
            try:
                protocol = Protocol[protocol_str.upper()]
            except KeyError:
                protocol = Protocol.ANY
                
            # Create a firewall rule to block the port
            rule = Rule(
                action=Action.DENY,
                protocol=protocol,
                destination_port=port,
                description=f"Auto-block port from IDS alert: {params.get('reason', 'Unknown')}",
                priority=150
            )
            
            self.rule_manager.add_rule(rule)
            return True
        except Exception as e:
            self.logger.error(f"Error handling block_port action: {e}")
            return False
    
    def _handle_block_connection(self, params: Dict[str, Any]) -> bool:
        try:
            src_ip = params.get('src_ip')
            dst_ip = params.get('dst_ip')
            dst_port = params.get('dst_port')
            protocol_str = params.get('protocol', 'any')
            
            if not (src_ip and dst_ip):
                return False
                
            try:
                protocol = Protocol[protocol_str.upper()]
            except KeyError:
                protocol = Protocol.ANY
                
            # Create a firewall rule to block the specific connection
            rule = Rule(
                action=Action.DENY,
                protocol=protocol,
                source_ip=src_ip,
                destination_ip=dst_ip,
                destination_port=dst_port,
                description=f"Auto-block connection from IDS alert: {params.get('reason', 'Unknown')}",
                priority=250  # Very high priority
            )
            
            self.rule_manager.add_rule(rule)
            return True
        except Exception as e:
            self.logger.error(f"Error handling block_connection action: {e}")
            return False
    
    def _add_default_response_rules(self):
        # Example rule: Block source IP for high priority alerts
        high_priority_rule = ResponseRule(
            name="block_high_priority_alerts",
            condition=lambda alert: alert.get('priority', 0) <= 2,  # Priority 1 and 2 are high
            action=ResponseAction.BLOCK_IP,
            parameters={
                "ip": lambda alert: alert.get('src_ip'),
                "reason": lambda alert: alert.get('message', 'High priority alert')
            },
            priority=100,
            description="Automatically block source IPs for high priority alerts",
            timeout=3600  # Auto-expire after 1 hour
        )
        
        self.response_system.add_response_rule(high_priority_rule)
        
        # More default rules can be added here