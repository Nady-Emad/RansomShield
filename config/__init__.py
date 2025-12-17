"""Configuration module - System-wide settings management.

Features:
- JSON and YAML configuration support
- HMAC-SHA256 signature verification
- Configuration validation
- Default configuration fallback
- Environment variable override support
- Type-safe configuration access

Modules:
- loader: Load configuration from JSON/YAML files
- validator: Validate configuration consistency and completeness

Usage:
    from config import ConfigLoader, ConfigValidator
    loader = ConfigLoader('config.json')
    cfg = loader.load()
    errors, valid = ConfigValidator.validate(cfg)
"""

from config.loader import ConfigLoader
from config.validator import ConfigValidator

__all__ = ['ConfigLoader', 'ConfigValidator']
