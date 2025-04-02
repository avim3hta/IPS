import yaml
import logging
from pathlib import Path
from typing import List, Dict, Optional, Union
from firewall.firewall_rules import Rule, Action, Protocol
from dataclasses import asdict

class RuleConfigurationError(Exception):
    pass

class RuleConfiguration:
    def __init__(self, config_file: Union[str, Path]):
        self.config_file = Path(config_file)
        self.logger = logging.getLogger(__name__)
        
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise RuleConfigurationError(f"Failed to create config directory: {e}")

    def load_rules(self) -> List[Rule]:
        try:
            if not self.config_file.exists():
                self.logger.warning(f"Config file not found: {self.config_file}")
                return []

            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f) or {}

            if not isinstance(config, dict) or 'rules' not in config:
                raise RuleConfigurationError("Invalid configuration format")

            rules = []
            for rule_config in config.get('rules', []):
                try:
                    if not self._validate_rule_config(rule_config):
                        continue
                    rule = self._create_rule_from_config(rule_config)
                    rules.append(rule)
                except Exception as e:
                    self.logger.error(f"Error creating rule: {e}")
                    continue

            return rules

        except yaml.YAMLError as e:
            raise RuleConfigurationError(f"YAML parsing error: {e}")
        except Exception as e:
            raise RuleConfigurationError(f"Error loading rules: {e}")

    def save_rules(self, rules: List[Rule]) -> bool:
        try:
            config = {'rules': [self._rule_to_dict(rule) for rule in rules]}
            
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            self.logger.info(f"Successfully saved {len(rules)} rules to {self.config_file}")
            return True

        except Exception as e:
            raise RuleConfigurationError(f"Error saving rules: {e}")

    def _validate_rule_config(self, config: Dict) -> bool:
        required_fields = {'action', 'protocol'}
        if not all(field in config for field in required_fields):
            self.logger.error(f"Missing required fields: {required_fields - set(config.keys())}")
            return False
            
        try:
            Action[config['action'].upper()]
            Protocol[config['protocol'].upper()]
            for port_key in ['source_port', 'destination_port']:
                if port_key in config and config[port_key] is not None:
                    port = int(config[port_key])
                    if not (0 <= port <= 65535):
                        raise ValueError(f"Invalid port number: {port}")
            return True
        except (KeyError, ValueError) as e:
            self.logger.error(f"Invalid rule configuration: {e}")
            return False

    def _create_rule_from_config(self, config: Dict) -> Rule:
        try:
            return Rule(
                action=Action[config['action'].upper()],
                protocol=Protocol[config['protocol'].upper()],
                source_ip=config.get('source_ip'),
                destination_ip=config.get('destination_ip'),
                source_port=config.get('source_port'),
                destination_port=config.get('destination_port'),
                priority=int(config.get('priority', 0)),
                description=str(config.get('description', '')),
                enabled=bool(config.get('enabled', True))
            )
        except Exception as e:
            raise ValueError(f"Invalid rule configuration: {e}")

    def _rule_to_dict(self, rule: Rule) -> Dict:
        rule_dict = asdict(rule)
        
        rule_dict['action'] = rule.action.value
        rule_dict['protocol'] = rule.protocol.value
        
        if rule.source_ip:
            rule_dict['source_ip'] = str(rule.source_ip)
        if rule.destination_ip:
            rule_dict['destination_ip'] = str(rule.destination_ip)
            
        return rule_dict