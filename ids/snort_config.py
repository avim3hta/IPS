from pathlib import Path
import subprocess
import logging
from typing import List, Dict, Optional

class SnortConfigError(Exception):
    pass

class SnortConfig:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)
        
    def validate_config(self) -> bool:
        try:
            result = subprocess.run(
                ["snort", "-T", "-c", str(self.config_path)],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                self.logger.error(f"Snort config validation failed: {result.stderr}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Error validating Snort config: {e}")
            return False
    
    def update_config(self, settings: Dict[str, str]) -> bool:
        if not self.config_path.exists():
            raise SnortConfigError(f"Config file does not exist: {self.config_path}")
        
        try:
            config_content = self.config_path.read_text()
            for key, value in settings.items():
                # Simple string replacement, might need more sophisticated parsing
                marker = f"# {key} setting"
                if marker in config_content:
                    old_line = config_content.split(marker)[1].split("\n")[0].strip()
                    new_line = f"{key} {value}"
                    config_content = config_content.replace(old_line, new_line)
            
            self.config_path.write_text(config_content)
            return self.validate_config()
        except Exception as e:
            self.logger.error(f"Error updating Snort config: {e}")
            return False
    
    def get_rule_paths(self) -> List[Path]:
        try:
            config_content = self.config_path.read_text()
            rule_paths = []
            for line in config_content.splitlines():
                if line.strip().startswith("include ") and ".rules" in line:
                    rule_path = line.split("include")[1].strip()
                    rule_paths.append(Path(rule_path))
            return rule_paths
        except Exception as e:
            self.logger.error(f"Error getting rule paths: {e}")
            return []