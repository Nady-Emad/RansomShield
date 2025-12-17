"""Config validation - Validate configuration consistency and completeness.

Features:
- Configuration schema validation
- Directory existence checking
- Type validation for config values
- Required key validation
- Comprehensive error reporting
- Non-destructive validation (read-only)

Validation Checks:
- All monitoring directories exist
- All thresholds are positive numbers
- All required keys present
- File paths are accessible
- Configuration structure is correct
"""

import os
from typing import Dict, List, Tuple, Any, Optional, Set


class SafeConfigValidator:
    """Safe configuration validation with error handling."""
    
    @staticmethod
    def safe_check_directory(directory: str) -> bool:
        """Safely check if directory exists.
        
        Args:
            directory: Directory path
            
        Returns:
            True if directory exists and accessible, False otherwise
        """
        try:
            if not isinstance(directory, str) or not directory:
                return False
            
            expanded = os.path.expanduser(directory)
            return os.path.isdir(expanded) and os.access(expanded, os.R_OK)
        
        except (TypeError, OSError, ValueError):
            return False
        except Exception:
            return False
    
    @staticmethod
    def safe_get_dict_value(d: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Safely get dictionary value with default.
        
        Args:
            d: Dictionary
            key: Key to retrieve
            default: Default value if key missing
            
        Returns:
            Value or default
        """
        try:
            if not isinstance(d, dict) or not isinstance(key, str):
                return default
            return d.get(key, default)
        except (TypeError, KeyError):
            return default
        except Exception:
            return default


class ConfigValidator:
    """Validate configuration consistency and completeness."""
    
    # Required configuration keys
    REQUIRED_KEYS: Set[str] = {'monitoring', 'detection', 'risk_scoring', 'correlation'}
    
    @staticmethod
    def validate(config: Optional[Dict[str, Any]]) -> Tuple[List[str], bool]:
        """Validate configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            (errors_list, is_valid) tuple
        """
        errors: List[str] = []
        
        try:
            if not config or not isinstance(config, dict):
                return ['Invalid config: not a dictionary'], False
            
            # Check required keys
            for key in ConfigValidator.REQUIRED_KEYS:
                if key not in config:
                    errors.append(f"Missing required key: {key}")
            
            # Validate monitoring section
            monitoring = SafeConfigValidator.safe_get_dict_value(config, 'monitoring', {})
            if isinstance(monitoring, dict):
                directories = monitoring.get('directories', [])
                if isinstance(directories, (list, tuple)):
                    for directory in directories:
                        if isinstance(directory, str):
                            if not SafeConfigValidator.safe_check_directory(directory):
                                errors.append(f"Monitoring directory not found or inaccessible: {directory}")
            
            # Validate detection section
            detection = SafeConfigValidator.safe_get_dict_value(config, 'detection', {})
            if isinstance(detection, dict):
                # Check burst threshold
                burst = detection.get('burst_threshold', {})
                if isinstance(burst, dict):
                    try:
                        threshold = burst.get('file_changes_per_window', 50)
                        if not isinstance(threshold, (int, float)) or threshold < 0:
                            errors.append("Invalid burst threshold: must be non-negative number")
                    except (TypeError, ValueError):
                        errors.append("Invalid burst threshold type")
            
            # Validate risk scoring section
            risk = SafeConfigValidator.safe_get_dict_value(config, 'risk_scoring', {})
            if isinstance(risk, dict):
                for key, value in risk.items():
                    try:
                        if isinstance(value, (int, float)) and value < 0:
                            errors.append(f"Risk scoring value must be non-negative: {key}")
                    except (TypeError, ValueError):
                        pass
            
            # Validate correlation section
            correlation = SafeConfigValidator.safe_get_dict_value(config, 'correlation', {})
            if isinstance(correlation, dict):
                try:
                    alert_threshold = correlation.get('alert_threshold')
                    if alert_threshold is not None:
                        if not isinstance(alert_threshold, (int, float)) or alert_threshold < 0:
                            errors.append("Alert threshold must be non-negative number")
                except (TypeError, ValueError):
                    errors.append("Invalid alert threshold")
            
            is_valid = len(errors) == 0
            return errors, is_valid
        
        except (TypeError, ValueError):
            return ['Configuration validation failed: invalid data'], False
        except Exception:
            return ['Configuration validation failed: unexpected error'], False
    
    @staticmethod
    def get_validation_summary(config: Optional[Dict[str, Any]]) -> str:
        """Get human-readable validation summary.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Summary string
        """
        try:
            errors, is_valid = ConfigValidator.validate(config)
            
            if is_valid:
                return "Configuration: VALID"
            else:
                summary = f"Configuration: INVALID ({len(errors)} issues)\n"
                for i, error in enumerate(errors[:5], 1):
                    summary += f"  {i}. {error}\n"
                
                if len(errors) > 5:
                    summary += f"  ... and {len(errors) - 5} more issues\n"
                
                return summary.strip()
        
        except Exception:
            return "Configuration validation: ERROR"
