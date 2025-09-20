"""
Pytest configuration and shared fixtures
"""

import pytest
import tempfile
import os
from pathlib import Path
from typing import Dict, Any

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)

@pytest.fixture
def sample_config() -> Dict[str, Any]:
    """Sample configuration for testing"""
    return {
        'analysis': {
            'python_version': '3.9',
            'include_patterns': ['*.py'],
            'exclude_patterns': ['test_*.py']
        },
        'iam': {
            'least_privilege': True,
            'resource_constraints': True
        },
        'security': {
            'check_hardcoded_secrets': True,
            'check_wildcard_permissions': True,
            'check_error_handling': True
        },
        'template': {
            'format': 'sam',
            'runtime': 'python3.9',
            'memory': 512,
            'timeout': 30
        }
    }

@pytest.fixture
def lambda_analyzer(sample_config):
    """Create a LambdaAnalyzer instance with test config"""
    from lambda_analyzer import LambdaAnalyzer
    return LambdaAnalyzer()