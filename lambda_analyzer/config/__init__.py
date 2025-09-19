"""
Configuration management for Lambda Analyzer
"""

import yaml
import os
from typing import Dict, Any


def load_default_config() -> Dict[str, Any]:
    """Load default configuration"""
    config_path = os.path.join(os.path.dirname(__file__), 'default.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def merge_config(default_config: Dict, user_config: Dict) -> Dict:
    """Merge user configuration with defaults"""
    merged = default_config.copy()

    for key, value in user_config.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key].update(value)
        else:
            merged[key] = value

    return merged