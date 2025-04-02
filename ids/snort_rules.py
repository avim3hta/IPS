from pathlib import Path
import re
import logging
from typing import List, Dict, Optional, Union

class SnortRule:
    def __init__(self, raw_rule: str):
        self.raw_rule = raw_rule.strip()
        self.enabled = not raw_rule.lstrip().startswith("#")
        self.parse_rule()
        
    def parse_rule(self):
        # Extract basic components from rule
        rule_pattern = r'(alert|log|pass|drop|reject|sdrop)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.*)\)'
        if not self.enabled:
            clean_rule = self.raw_rule.lstrip("#").strip()
        else:
            clean_rule = self.raw_rule
            
        match = re.match(rule_pattern, clean_rule)
        if match:
            self.action = match.group(1)
            self.protocol = match.group(2)
            self.src_ip = match.group(3)
            self.src_port = match.group(4)
            self.dst_ip = match.group(5)
            self.dst_port = match.group(6)
            self.options = match.group(7)
            
            # Extract rule metadata
            if "msg:" in self.options:
                msg_match = re.search(r'msg:"([^"]+)"', self.options)
                self.message = msg_match.group(1) if msg_match else ""
            else:
                self.message = ""
                
            if "sid:" in self.options:
                sid_match = re.search(r'sid:(\d+)', self.options)
                self.sid = sid_match.group(1) if sid_match else ""
            else:
                self.sid = ""
        else:
            # Handle parsing failure
            self.action = None
            self.protocol = None
            self.src_ip = None
            self.src_port = None
            self.dst_ip = None
            self.dst_port = None
            self.options = None
            self.message = None
            self.sid = None
    
    def to_string(self) -> str:
        if self.action is None:  # Parsing failed, return original
            return self.raw_rule
            
        prefix = "#" if not self.enabled else ""
        rule_text = f"{self.action} {self.protocol} {self.src_ip} {self.src_port} -> {self.dst_ip} {self.dst_port} ({self.options})"
        return prefix + rule_text
    
    def enable(self):
        self.enabled = True
    
    def disable(self):
        self.enabled = False

class SnortRuleManager:
    def __init__(self):
        self.rules = []
        self.rules_by_sid = {}
        self.logger = logging.getLogger(__name__)
    
    def load_rules_file(self, rules_file: Union[str, Path]) -> bool:
        try:
            path = Path(rules_file)
            if not path.exists():
                self.logger.error(f"Rules file not found: {path}")
                return False
                
            with open(path, 'r') as f:
                file_content = f.read()
                
            # Process rules in file
            raw_rules = []
            current_rule = ""
            
            for line in file_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") and not any(action in line for action in ["alert", "log", "pass", "drop", "reject", "sdrop"]):
                    continue
                    
                if line.endswith("\\"):
                    current_rule += line[:-1].strip() + " "
                else:
                    current_rule += line
                    if current_rule.strip():
                        raw_rules.append(current_rule)
                    current_rule = ""
            
            # Parse each rule
            for raw_rule in raw_rules:
                rule = SnortRule(raw_rule)
                if rule.sid:
                    self.rules.append(rule)
                    self.rules_by_sid[rule.sid] = rule
            
            self.logger.info(f"Loaded {len(self.rules)} rules from {path}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading rules file: {e}")
            return False
    
    def get_rule_by_sid(self, sid: str) -> Optional[SnortRule]:
        return self.rules_by_sid.get(sid)
    
    def save_rules_file(self, rules_file: Union[str, Path]) -> bool:
        try:
            path = Path(rules_file)
            with open(path, 'w') as f:
                for rule in self.rules:
                    f.write(rule.to_string() + "\n")
            return True
        except Exception as e:
            self.logger.error(f"Error saving rules file: {e}")
            return False