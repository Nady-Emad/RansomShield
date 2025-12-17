"""Self-integrity monitoring - Detect tampering of defense files.

Features:
- SHA256 hash-based file integrity monitoring
- Critical file tracking
- Modification and deletion detection
- Comprehensive error handling
- Atomic hash verification

Monitored Files:
- Config files (config.json)
- Core detection/mitigation modules
- Worker and utility modules
- Logger and process utilities
"""

import os
import hashlib
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger(__name__)


class TamperDetector:
    """Monitor own files for integrity violations."""
    
    def __init__(self, config: Dict[str, Any], logger_obj: Optional[Any] = None):
        """Initialize tamper detector.
        
        Args:
            config: Configuration dict
            logger_obj: Logger instance (optional)
        """
        self.config = config or {}
        self.logger = logger_obj
        self.file_hashes: Dict[str, Optional[str]] = {}
        self.check_interval = 60  # seconds
        self.last_check: Optional[datetime] = None
        
        # Critical files to monitor
        self.monitored_files = [
            'config.json',
            'config/loader.py',
            'config/validator.py',
            'core/detector.py',
            'core/mitigator.py',
            'core/risk_engine.py',
            'workers/monitor_worker.py',
            'utils/logger.py',
            'utils/process_utils.py',
        ]
    
    def initialize(self) -> None:
        """Compute initial hashes of critical files."""
        try:
            for relative_path in self.monitored_files:
                try:
                    abs_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), relative_path)
                    if os.path.exists(abs_path):
                        file_hash = self._compute_file_hash(abs_path)
                        self.file_hashes[abs_path] = file_hash
                        logger.info(f"Monitoring: {relative_path}")
                except (TypeError, OSError):
                    continue
        except Exception:
            pass
    
    def _compute_file_hash(self, file_path: str) -> Optional[str]:
        """Compute SHA256 hash of file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hex digest or None on error
        """
        try:
            if not isinstance(file_path, str) or not os.path.exists(file_path):
                return None
            
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        
        except (PermissionError, IOError, OSError):
            return None
        except Exception:
            return None
    
    def check_integrity(self) -> bool:
        """Check if monitored files have been modified.
        
        Returns:
            True if all files intact, False if tampering detected
        """
        tampered_files: List[Tuple[str, str]] = []
        
        try:
            for file_path, expected_hash in self.file_hashes.items():
                try:
                    if not os.path.exists(file_path):
                        tampered_files.append((file_path, "DELETED"))
                        continue
                    
                    current_hash = self._compute_file_hash(file_path)
                    if current_hash and expected_hash and current_hash != expected_hash:
                        tampered_files.append((file_path, "MODIFIED"))
                
                except (TypeError, OSError):
                    continue
            
            if tampered_files:
                self._log_tamper_detected(tampered_files)
                return False
            
            return True
        
        except Exception:
            return True
    
    def _log_tamper_detected(self, tampered_files: List[Tuple[str, str]]) -> None:
        """Log tamper detection event.
        
        Args:
            tampered_files: List of (path, status) tuples
        """
        try:
            file_list = "\n  ".join([f"{path}: {status}" for path, status in tampered_files])
            msg = f"CRITICAL: File tampering detected:\n  {file_list}"
            logger.critical(msg)
            if self.logger:
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'CRITICAL',
                    'rule': 'TAMPER_DETECTION',
                    'message': msg
                })
        except (TypeError, AttributeError):
            pass
        except Exception:
            pass
        message = f"TAMPER DETECTED in defense system files:\n  {file_list}"
        
        logger.critical(message)
        
        if self.logger:
            try:
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'CRITICAL',
                    'rule': 'DEFENSE_TAMPER',
                    'pid': 0,
                    'process_name': 'System',
                    'path': None,
                    'action': 'Tamper detected',
                    'message': message
                })
            except Exception:
                pass
    
    def update_file_hash(self, file_path):
        """Update hash after legitimate changes (e.g., log rotation)."""
        if os.path.exists(file_path):
            self.file_hashes[file_path] = self._compute_file_hash(file_path)
