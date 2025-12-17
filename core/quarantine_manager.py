"""Quarantine Manager - Safe file isolation and restoration.

Features:
- Atomic file moves to quarantine
- Comprehensive metadata logging
- File hash verification (SHA256)
- Restoration capability
- Date-based organization
- Thread-safe operations
- Comprehensive error handling

Storage:
- Quarantine base directory
- Date-based subdirectories (YYYYMMDD)
- Metadata JSON file for tracking
- Original path preservation
"""

import os
import shutil
import json
import hashlib
from datetime import datetime
from pathlib import Path
import threading
from typing import Dict, Optional, Any, List, Tuple


class SafeQuarantineAccess:
    """Safe file operations for quarantine."""
    
    @staticmethod
    def safe_move_file(src: str, dst: str) -> Tuple[bool, Optional[str]]:
        """Safely move file with error handling.
        
        Args:
            src: Source path
            dst: Destination path
            
        Returns:
            (success, error_msg) tuple
        """
        try:
            if not isinstance(src, str) or not isinstance(dst, str):
                return False, "Invalid paths"
            
            if not os.path.exists(src):
                return False, "Source not found"
            
            shutil.move(src, dst)
            return True, None
        
        except (PermissionError, IOError, OSError) as e:
            return False, str(e)[:50]
        except Exception:
            return False, "Move failed"
    
    @staticmethod
    def safe_compute_hash(filepath: str) -> Optional[str]:
        """Safely compute file hash.
        
        Args:
            filepath: Path to file
            
        Returns:
            Hex digest or None on error
        """
        try:
            if not isinstance(filepath, str) or not os.path.exists(filepath):
                return None
            
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        
        except (PermissionError, IOError, OSError):
            return None
        except Exception:
            return None


class QuarantineManager:
    """
    Manages quarantined files with:
    - Atomic file moves
    - Metadata logging
    - Restoration capability
    - Hash verification
    """
    
    def __init__(self, quarantine_dir, logger):
        """
        Initialize quarantine manager.
        
        Args:
            quarantine_dir: Base quarantine directory path
            logger: Logger instance
        """
        self.quarantine_dir = Path(quarantine_dir)
        self.logger = logger
        self._lock = threading.Lock()
        
        # Create quarantine directory structure
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Metadata file
        self.metadata_file = self.quarantine_dir / 'quarantine_metadata.json'
        self.metadata = self._load_metadata()
    
    def quarantine_file(self, filepath, reason, score, severity):
        """
        Quarantine a file atomically.
        
        Args:
            filepath: Original file path
            reason: Detection reason
            score: Threat score
            severity: Threat severity
        
        Returns:
            dict: Quarantine result
        """
        with self._lock:
            try:
                if not os.path.exists(filepath):
                    return {'success': False, 'error': 'File not found'}
                
                # Create date-based subfolder
                date_folder = datetime.now().strftime('%Y%m%d')
                quarantine_subdir = self.quarantine_dir / date_folder
                quarantine_subdir.mkdir(exist_ok=True)
                
                # Generate unique filename
                original_name = os.path.basename(filepath)
                timestamp = datetime.now().strftime('%H%M%S')
                quarantine_name = f"{timestamp}_{original_name}"
                quarantine_path = quarantine_subdir / quarantine_name
                
                # Compute hash before move
                file_hash = self._compute_hash(filepath)
                
                # Get file metadata
                file_stats = os.stat(filepath)
                
                # Move file atomically
                shutil.move(filepath, str(quarantine_path))
                
                # Record metadata
                metadata_entry = {
                    'original_path': filepath,
                    'quarantine_path': str(quarantine_path),
                    'timestamp': datetime.now().isoformat(),
                    'reason': reason,
                    'score': score,
                    'severity': severity,
                    'hash_sha256': file_hash,
                    'size': file_stats.st_size,
                    'original_modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                    'restored': False
                }
                
                self.metadata[file_hash] = metadata_entry
                self._save_metadata()
                
                # Log quarantine action
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'INFO',
                    'rule': 'QUARANTINE',
                    'path': filepath,
                    'message': f'File quarantined: {reason}'
                })
                
                return {
                    'success': True,
                    'quarantine_path': str(quarantine_path),
                    'hash': file_hash
                }
            
            except Exception as e:
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'ERROR',
                    'rule': 'QUARANTINE_ERROR',
                    'path': filepath,
                    'message': f'Quarantine failed: {str(e)}'
                })
                
                return {'success': False, 'error': str(e)}
    
    def restore_file(self, file_hash):
        """
        Restore a quarantined file.
        
        Args:
            file_hash: SHA256 hash of the file
        
        Returns:
            dict: Restoration result
        """
        with self._lock:
            try:
                if file_hash not in self.metadata:
                    return {'success': False, 'error': 'File not found in quarantine'}
                
                entry = self.metadata[file_hash]
                
                if entry['restored']:
                    return {'success': False, 'error': 'File already restored'}
                
                quarantine_path = entry['quarantine_path']
                original_path = entry['original_path']
                
                if not os.path.exists(quarantine_path):
                    return {'success': False, 'error': 'Quarantine file missing'}
                
                # Verify hash
                current_hash = self._compute_hash(quarantine_path)
                if current_hash != file_hash:
                    return {'success': False, 'error': 'File integrity check failed'}
                
                # Create parent directory if needed
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                
                # Restore file
                shutil.move(quarantine_path, original_path)
                
                # Update metadata
                entry['restored'] = True
                entry['restore_timestamp'] = datetime.now().isoformat()
                self._save_metadata()
                
                # Log restoration
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'INFO',
                    'rule': 'RESTORE',
                    'path': original_path,
                    'message': 'File restored from quarantine'
                })
                
                return {'success': True, 'restored_path': original_path}
            
            except Exception as e:
                return {'success': False, 'error': str(e)}
    
    def delete_quarantined(self, file_hash):
        """
        Permanently delete a quarantined file.
        
        Args:
            file_hash: SHA256 hash of the file
        
        Returns:
            dict: Deletion result
        """
        with self._lock:
            try:
                if file_hash not in self.metadata:
                    return {'success': False, 'error': 'File not found'}
                
                entry = self.metadata[file_hash]
                quarantine_path = entry['quarantine_path']
                
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
                
                # Remove from metadata
                del self.metadata[file_hash]
                self._save_metadata()
                
                return {'success': True}
            
            except Exception as e:
                return {'success': False, 'error': str(e)}
    
    def get_quarantined_files(self):
        """
        Get list of all quarantined files.
        
        Returns:
            list: Quarantined file metadata
        """
        return [entry for entry in self.metadata.values() if not entry['restored']]
    
    def _compute_hash(self, filepath):
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def _load_metadata(self):
        """Load quarantine metadata from disk."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    
    def _save_metadata(self):
        """Save quarantine metadata to disk."""
        try:
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.log_event({
                'timestamp': datetime.now().isoformat(),
                'severity': 'ERROR',
                'rule': 'METADATA_ERROR',
                'message': f'Failed to save quarantine metadata: {str(e)}'
            })
