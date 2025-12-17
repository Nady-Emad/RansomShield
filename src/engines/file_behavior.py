"""
File Behavior Engine
Monitors file system activities, detects rapid encryption patterns,
calculates entropy for ransomware detection
"""

import os
import time
import math
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class FileBehaviorEngine:
    """
    Monitors file system for ransomware-like behaviors:
    - Rapid file modifications/deletions
    - High entropy files (encrypted)
    - Suspicious file extensions
    - Mass file operations
    """
    
    # Suspicious file extensions commonly used by ransomware
    RANSOMWARE_EXTENSIONS = {
        '.encrypted', '.locked', '.crypto', '.crypt', '.crypted',
        '.enc', '.locky', '.cerber', '.zepto', '.vault',
        '.wcry', '.wncry', '.wannacry', '.wncryt',
        '.exx', '.ezz', '.ecc', '.aaa', '.abc', '.xyz',
        '.zzz', '.micro', '.dharma', '.wallet', '.onion'
    }
    
    def __init__(self, 
                 threshold_files_per_second: int = 10,
                 entropy_threshold: float = 7.0,
                 time_window_seconds: int = 5):
        """
        Initialize File Behavior Engine
        
        Args:
            threshold_files_per_second: Alert if more files modified per second
            entropy_threshold: Entropy value indicating encryption (0-8, 8=random)
            time_window_seconds: Time window for rate calculation
        """
        self.threshold_fps = threshold_files_per_second
        self.entropy_threshold = entropy_threshold
        self.time_window = time_window_seconds
        
        # Track file operations
        self.file_operations: deque = deque(maxlen=1000)
        self.file_rename_pairs: Dict[str, str] = {}
        self.entropy_cache: Dict[str, float] = {}
        
        # Statistics
        self.total_files_monitored = 0
        self.suspicious_files = 0
        self.high_entropy_files = 0
        
        # Alert tracking
        self.alerts: List[Dict] = []
        
    def calculate_entropy(self, file_path: str, sample_size: int = 8192) -> float:
        """
        Calculate Shannon entropy of a file
        High entropy (>7.0) often indicates encryption
        
        Args:
            file_path: Path to file
            sample_size: Number of bytes to sample
            
        Returns:
            Entropy value (0-8)
        """
        try:
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                return 0.0
                
            # Read sample
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
            
            if len(data) == 0:
                return 0.0
            
            # Calculate byte frequency
            freq = defaultdict(int)
            for byte in data:
                freq[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in freq.values():
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except (IOError, PermissionError):
            return 0.0
    
    def is_suspicious_extension(self, file_path: str) -> bool:
        """Check if file has suspicious ransomware extension"""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.RANSOMWARE_EXTENSIONS
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a single file for ransomware indicators
        
        Returns:
            Dictionary with analysis results
        """
        result = {
            'path': file_path,
            'suspicious': False,
            'reasons': [],
            'risk_score': 0.0,
            'entropy': 0.0
        }
        
        # Check extension
        if self.is_suspicious_extension(file_path):
            result['suspicious'] = True
            result['reasons'].append('suspicious_extension')
            result['risk_score'] += 40.0
        
        # Calculate entropy
        entropy = self.calculate_entropy(file_path)
        result['entropy'] = entropy
        
        if entropy >= self.entropy_threshold:
            result['suspicious'] = True
            result['reasons'].append('high_entropy')
            result['risk_score'] += 30.0
            self.high_entropy_files += 1
        
        if result['suspicious']:
            self.suspicious_files += 1
        
        return result
    
    def record_operation(self, operation_type: str, file_path: str) -> None:
        """Record file operation with timestamp"""
        self.file_operations.append({
            'type': operation_type,
            'path': file_path,
            'timestamp': time.time()
        })
        self.total_files_monitored += 1
    
    def get_operation_rate(self) -> float:
        """
        Calculate current file operation rate
        
        Returns:
            Operations per second
        """
        if not self.file_operations:
            return 0.0
        
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        # Count operations within time window
        recent_ops = [op for op in self.file_operations 
                     if op['timestamp'] >= cutoff_time]
        
        if not recent_ops:
            return 0.0
        
        time_span = current_time - recent_ops[0]['timestamp']
        if time_span == 0:
            return len(recent_ops)
        
        return len(recent_ops) / time_span
    
    def detect_mass_encryption(self) -> Optional[Dict]:
        """
        Detect mass encryption activity
        
        Returns:
            Alert dictionary if detected, None otherwise
        """
        rate = self.get_operation_rate()
        
        if rate > self.threshold_fps:
            # Check for high entropy files
            current_time = time.time()
            cutoff_time = current_time - self.time_window
            
            recent_ops = [op for op in self.file_operations 
                         if op['timestamp'] >= cutoff_time]
            
            high_entropy_count = 0
            for op in recent_ops:
                if op['path'] in self.entropy_cache:
                    if self.entropy_cache[op['path']] >= self.entropy_threshold:
                        high_entropy_count += 1
            
            if high_entropy_count > self.threshold_fps / 2:
                alert = {
                    'type': 'mass_encryption',
                    'severity': 'critical',
                    'rate': rate,
                    'threshold': self.threshold_fps,
                    'high_entropy_files': high_entropy_count,
                    'timestamp': current_time,
                    'message': f'Mass encryption detected: {rate:.2f} files/sec'
                }
                self.alerts.append(alert)
                return alert
        
        return None
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        return {
            'total_files_monitored': self.total_files_monitored,
            'suspicious_files': self.suspicious_files,
            'high_entropy_files': self.high_entropy_files,
            'current_operation_rate': self.get_operation_rate(),
            'alerts_generated': len(self.alerts)
        }
    
    def reset(self) -> None:
        """Reset engine state"""
        self.file_operations.clear()
        self.file_rename_pairs.clear()
        self.entropy_cache.clear()
        self.alerts.clear()
        self.total_files_monitored = 0
        self.suspicious_files = 0
        self.high_entropy_files = 0


class FileSystemWatcher(FileSystemEventHandler):
    """Watchdog event handler for file system monitoring"""
    
    def __init__(self, engine: FileBehaviorEngine):
        self.engine = engine
        super().__init__()
    
    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.engine.record_operation('modified', event.src_path)
    
    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.engine.record_operation('created', event.src_path)
    
    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.engine.record_operation('deleted', event.src_path)
    
    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.engine.record_operation('moved', event.dest_path)
