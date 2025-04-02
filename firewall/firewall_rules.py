from dataclasses import dataclass, field
from typing import Optional, Union, List, Dict
from ipaddress import IPv4Network, IPv4Address, ip_address, ip_network
from enum import Enum
import uuid
import logging
from datetime import datetime

class Action(Enum):
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"

class RuleValidationError(Exception):
    pass

@dataclass
class Rule:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: Action = Action.DENY
    protocol: Protocol = Protocol.ANY
    source_ip: Optional[Union[str, IPv4Network, IPv4Address]] = None
    destination_ip: Optional[Union[str, IPv4Network, IPv4Address]] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    priority: int = 0
    description: str = ""
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    modified_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        try:
            self._validate_ports()
            self._validate_and_convert_ips()
            self._validate_protocol_port_combination()
        except ValueError as e:
            raise RuleValidationError(f"Rule validation failed: {str(e)}")

    def _validate_ports(self):
        for port_name, port in [("Source", self.source_port), 
                              ("Destination", self.destination_port)]:
            if port is not None:
                if not isinstance(port, int):
                    raise ValueError(f"{port_name} port must be an integer")
                if not 0 <= port <= 65535:
                    raise ValueError(
                        f"{port_name} port must be between 0 and 65535"
                    )

    def _validate_and_convert_ips(self):
        for ip_attr in ['source_ip', 'destination_ip']:
            ip_value = getattr(self, ip_attr)
            if ip_value is not None:
                if isinstance(ip_value, str):
                    try:
                        setattr(self, ip_attr, ip_network(ip_value, strict=False))
                    except ValueError:
                        try:
                            setattr(self, ip_attr, ip_address(ip_value))
                        except ValueError as e:
                            raise ValueError(
                                f"Invalid IP address/network for {ip_attr}: {str(e)}"
                            )

    def _validate_protocol_port_combination(self):
        has_ports = self.source_port is not None or self.destination_port is not None
        
        if has_ports and self.protocol not in (Protocol.TCP, Protocol.UDP, Protocol.ANY):
            raise ValueError(
                "Ports can only be specified for TCP, UDP, or ANY protocols"
            )

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise AttributeError(f"Invalid rule attribute: {key}")
        
        self.modified_at = datetime.now()
        self.__post_init__()

class RuleManager:
    def __init__(self):
        self.rules: List[Rule] = []
        self.default_action = Action.DENY
        self.logger = logging.getLogger(__name__)
        self.rules_by_id: Dict[str, Rule] = {}

    def add_rule(self, rule: Rule) -> None:
        if rule.id in self.rules_by_id:
            raise ValueError(f"Rule with ID {rule.id} already exists")
            
        self.rules.append(rule)
        self.rules_by_id[rule.id] = rule
        self._sort_rules()
        
        self.logger.info(
            f"Added rule {rule.id}: {rule.description} "
            f"(Priority: {rule.priority})"
        )

    def remove_rule(self, rule_id: str) -> bool:
        if rule_id in self.rules_by_id:
            rule = self.rules_by_id[rule_id]
            self.rules.remove(rule)
            del self.rules_by_id[rule_id]
            self.logger.info(f"Removed rule {rule_id}")
            return True
        return False

    def update_rule(self, rule_id: str, **kwargs) -> bool:
        if rule_id in self.rules_by_id:
            rule = self.rules_by_id[rule_id]
            try:
                rule.update(**kwargs)
                self._sort_rules()
                self.logger.info(f"Updated rule {rule_id}")
                return True
            except Exception as e:
                self.logger.error(f"Error updating rule {rule_id}: {str(e)}")
                raise
        return False

    def _sort_rules(self) -> None:
        self.rules.sort(key=lambda x: (-x.priority, x.created_at))

    def evaluate_packet(self, packet_info: dict) -> Action:
        for rule in self.rules:
            if not rule.enabled:
                continue

            try:
                if self._packet_matches_rule(packet_info, rule):
                    self.logger.debug(
                        f"Packet matched rule {rule.id}: {rule.description}"
                    )
                    return rule.action
            except Exception as e:
                self.logger.error(
                    f"Error evaluating packet against rule {rule.id}: {str(e)}"
                )
                continue

        return self.default_action

    def _packet_matches_rule(self, packet_info: dict, rule: Rule) -> bool:
        try:
            if (rule.protocol != Protocol.ANY and 
                packet_info['protocol'] != rule.protocol.value):
                return False

            if rule.source_ip:
                packet_src_ip = ip_address(packet_info['src_ip'])
                if isinstance(rule.source_ip, IPv4Network):
                    if packet_src_ip not in rule.source_ip:
                        return False
                elif packet_src_ip != rule.source_ip:
                    return False

            if rule.destination_ip:
                packet_dst_ip = ip_address(packet_info['dst_ip'])
                if isinstance(rule.destination_ip, IPv4Network):
                    if packet_dst_ip not in rule.destination_ip:
                        return False
                elif packet_dst_ip != rule.destination_ip:
                    return False

            if packet_info['protocol'] in ('tcp', 'udp'):
                if (rule.source_port and 
                    packet_info.get('src_port') != rule.source_port):
                    return False
                
                if (rule.destination_port and 
                    packet_info.get('dst_port') != rule.destination_port):
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Error matching rule: {str(e)}")
            return False

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        return self.rules_by_id.get(rule_id)

    def get_rules(self) -> List[Rule]:
        return self.rules.copy()

    def get_rules_by_priority(self, min_priority: int = None, 
                            max_priority: int = None) -> List[Rule]:
        rules = self.rules.copy()
        if min_priority is not None:
            rules = [r for r in rules if r.priority >= min_priority]
        if max_priority is not None:
            rules = [r for r in rules if r.priority <= max_priority]
        return rules