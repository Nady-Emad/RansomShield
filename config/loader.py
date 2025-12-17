"""Config loader - Load and verify configuration files.

Features:
- JSON and YAML file support
- HMAC-SHA256 signature verification for config integrity
- Automatic fallback to defaults on error
- Environment variable override support
- Type-safe configuration access
- Comprehensive error handling

Signature Verification:
- Optional HMAC signing via RDK_CONFIG_KEY environment variable
- Prevents unauthorized config tampering
- Graceful fallback if signature missing

Defaults:
- Complete default configuration if file not found
- All detection engines enabled
- Safe monitor-only mode by default
"""

import json
import os
import base64
import hmac
import hashlib
from typing import Dict, Optional, Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class SafeConfigAccess:
    """Safe configuration file operations with error handling."""
    
    @staticmethod
    def safe_read_json(filepath: str) -> Optional[Dict[str, Any]]:
        """Safely read JSON configuration file.
        
        Args:
            filepath: Path to JSON file
            
        Returns:
            Config dict or None on error
        """
        try:
            if not isinstance(filepath, str) or not os.path.exists(filepath):
                return None
            
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        except (json.JSONDecodeError, ValueError):
            return None
        except (PermissionError, IOError, OSError):
            return None
        except Exception:
            return None
    
    @staticmethod
    def safe_read_yaml(filepath: str) -> Optional[Dict[str, Any]]:
        """Safely read YAML configuration file.
        
        Args:
            filepath: Path to YAML file
            
        Returns:
            Config dict or None on error
        """
        if not YAML_AVAILABLE:
            return None
        
        try:
            if not isinstance(filepath, str) or not os.path.exists(filepath):
                return None
            
            with open(filepath, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        
        except (yaml.YAMLError, ValueError):
            return None
        except (PermissionError, IOError, OSError):
            return None
        except Exception:
            return None


class ConfigLoader:
    """Load configuration with optional integrity verification."""
    
    def __init__(self, path: str = 'config.json', secret_key: Optional[str] = None):
        """Initialize config loader.
        
        Args:
            path: Path to configuration file (JSON or YAML)
            secret_key: Secret key for HMAC verification (or from RDK_CONFIG_KEY env)
        """
        self.path = path
        self.secret_key = secret_key or os.environ.get('RDK_CONFIG_KEY')
    
    def load(self, custom_path: Optional[str] = None) -> Dict[str, Any]:
        """Load config from file with fallback to defaults.
        
        Args:
            custom_path: Optional override for config file path
            
        Returns:
            Configuration dictionary
        """
        try:
            path = custom_path or self.path
            
            if not isinstance(path, str):
                return self._get_defaults()
            
            # Detect file format
            if path.lower().endswith(('.yaml', '.yml')):
                if YAML_AVAILABLE:
                    data = SafeConfigAccess.safe_read_yaml(path)
                else:
                    data = None
            else:
                data = SafeConfigAccess.safe_read_json(path)
            
            if not data or not isinstance(data, dict):
                return self._get_defaults()
            
            # Optional signature verification
            signature = data.pop('signature', None)
            if self.secret_key and signature:
                if not self._verify_signature(data, signature):
                    return self._get_defaults()
            
            return data
        
        except (TypeError, ValueError):
            return self._get_defaults()
        except Exception:
            return self._get_defaults()
    
    def _verify_signature(self, config_dict: Dict[str, Any], signature_b64: str) -> bool:
        """Verify HMAC-SHA256 signature.
        
        Args:
            config_dict: Configuration dictionary
            signature_b64: Base64-encoded signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if not isinstance(config_dict, dict) or not isinstance(signature_b64, str):
                return False
            
            if not self.secret_key or not isinstance(self.secret_key, str):
                return False
            
            serialized = json.dumps(config_dict, sort_keys=True).encode()
            mac = hmac.new(self.secret_key.encode(), serialized, hashlib.sha256).digest()
            expected = base64.b64encode(mac).decode()
            
            return hmac.compare_digest(expected, signature_b64)
        
        except (TypeError, ValueError, AttributeError):
            return False
        except Exception:
            return False
    
    def _get_defaults(self) -> Dict[str, Any]:
        """Return default configuration.
        
        Returns:
            Complete default configuration dictionary
        """
        return {
            'monitoring': {
                'enabled': True,
                'directories': [os.path.expanduser('~/Documents')],
                'recursive': True
            },
            'canary': {
                'enabled': True,
                'filename': '.opsguard_canary'
            },
            'detection': {
                'burst_threshold': {
                    'file_changes_per_window': 50,
                    'time_window_seconds': 10
                },
                'backup_delete_keywords': ['vssadmin', 'wmic'],
                'cpu_monitor': {
                    'enabled': True,
                    'interval_seconds': 1,
                    'cpu_percent_threshold': 40,
                    'write_bytes_threshold': 5000000
                },
                'cli_monitor': {
                    'enabled': True,
                    'patterns': [
                        'vssadmin delete shadows',
                        'wmic shadowcopy delete',
                        'bcdedit /set {default} recoveryenabled no',
                        'wbadmin delete catalog'
                    ]
                },
                'network_monitor': {'enabled': False},
                'suspicious_extensions': [
                    '.exe', '.dll', '.sys', '.scr', '.com',
                    '.locked', '.crypt', '.encrypted'
                ],
                'extension_anomaly': {
                    'random_suffix_min': 5,
                    'random_suffix_max': 8,
                    'trigger_count': 5
                },
                'hot_zones': ['Documents', 'Desktop', 'Pictures', 'Downloads']
            },
            'risk_scoring': {
                'canary_tamper_score': 100,
                'burst_activity_score': 50,
                'backup_deletion_indicator_score': 80,
                'mitigation_threshold': 120,
                'score_decay_per_minute': 5
            },
            'correlation': {
                'alert_threshold': 70,
                'kill_threshold': 120,
                'score_weights': {
                    'FILE_BURST': 25,
                    'HOTZONE_BURST': 20,
                    'EXTENSION_ANOMALY': 30,
                    'CPU_IO_SPIKE': 25,
                    'BACKUP_TAMPER': 120,
                    'CANARY_TAMPER': 100
                }
            },
            'mitigation': {
                'mode': 'monitor-only',
                'cooldown_seconds': 30
            },
            'whitelist': {'process_names': []},
            'logging': {
                'jsonl_file': './logs/events.jsonl',
                'csv_file': './logs/summary.csv'
            }
        }
