"""
Ultra-sensitive file behavior monitoring engine.
Detects encryption patterns, suspicious extensions, and entropy changes.
"""

import os
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class FileActivityBucket:
    """Tracks file activity metrics for per-PID analysis."""
    
    def __init__(self, pid, process_name, window_size=30):
        self.pid = pid
        self.process_name = process_name
        self.window_size = window_size  # seconds
        self.window_start = time.time()
        
        # Activity counters
        self.file_creates = deque(maxlen=1000)
        self.file_renames = deque(maxlen=1000)
        self.file_deletes = deque(maxlen=1000)
        self.file_writes = deque(maxlen=5000)
        
        # Extension tracking
        self.extensions_seen = defaultdict(int)
        self.bytes_written = 0
        self.suspicious_extension_count = 0
        
        # Entropy tracking
        self.file_entropies = []
        self.avg_entropy = 0.0
    
    def add_create(self, path, size=0):
        """Log file creation."""
        self.file_creates.append((time.time(), path, size))
    
    def add_rename(self, src, dst, size=0):
        """Log file rename/move."""
        self.file_renames.append((time.time(), src, dst, size))
        
        # Track extension change
        src_ext = os.path.splitext(src)[1].lower()
        dst_ext = os.path.splitext(dst)[1].lower()
        
        self.extensions_seen[dst_ext] += 1
        
        # Check for suspicious extensions
        suspicious = [
            '.locked', '.encrypted', '.ransomware', '.crypto', '.crypt',
            '.enc', '.kraken', '.cerber', '.locky', '.wcry', '.onion',
            '.zzz', '.xyz', '.abc', '.key', '.virus', '.help', '.slock',
            '.ecc', '.elob', '.vvv', '.ttt', '.00000001'
        ]
        
        if dst_ext in suspicious:
            self.suspicious_extension_count += 1
    
    def add_delete(self, path):
        """Log file deletion."""
        self.file_deletes.append((time.time(), path))
    
    def add_write(self, path, bytes_written):
        """Log file write operation."""
        self.file_writes.append((time.time(), path, bytes_written))
        self.bytes_written += bytes_written
    
    def calculate_entropy(self, file_path):
        """
        Calculate Shannon entropy of file.
        High entropy = likely encrypted (>7.8 indicates strong encryption).
        
        SECURITY FIX: Prevents TOCTOU race condition by using file descriptor.
        """
        try:
            import math
            
            # SECURITY FIX: Open file once and keep descriptor to prevent TOCTOU
            # Old code: check size, then open - file could be swapped in between
            with open(file_path, 'rb') as f:
                # Get size from file descriptor (not filesystem)
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()
                f.seek(0)  # Seek back to start
                
                # Read sample from the SAME file descriptor
                sample_size = min(65536, file_size)
                if sample_size == 0:
                    return 0.0
                    
                data = f.read(sample_size)
            
            if not data:
                return 0.0
            
            entropy = 0.0
            for byte_val in range(256):
                freq = data.count(bytes([byte_val])) / len(data)
                if freq > 0:
                    entropy -= freq * math.log2(freq)  # Correct Shannon entropy formula
            
            self.file_entropies.append(entropy)
            self.avg_entropy = sum(self.file_entropies) / len(self.file_entropies)
            return entropy
        except Exception as e:
            logger.warning(f"Failed to calculate entropy for {file_path}: {e}")
            return 0.0
    
    def get_metrics(self):
        """Return activity metrics for scoring."""
        now = time.time()
        
        # Count events in current window
        recent_creates = sum(1 for t, _, _ in self.file_creates if now - t < self.window_size)
        recent_renames = sum(1 for t, _, _, _ in self.file_renames if now - t < self.window_size)
        recent_deletes = sum(1 for t, _ in self.file_deletes if now - t < self.window_size)
        recent_writes = sum(1 for t, _, _ in self.file_writes if now - t < self.window_size)
        recent_bytes = sum(b for t, _, b in self.file_writes if now - t < self.window_size)
        
        return {
            'recent_creates': recent_creates,
            'recent_renames': recent_renames,
            'recent_deletes': recent_deletes,
            'recent_writes': recent_writes,
            'recent_bytes': recent_bytes,
            'suspicious_extensions': self.suspicious_extension_count,
            'avg_entropy': self.avg_entropy,
            'total_activity': recent_creates + recent_renames + recent_deletes + recent_writes,
        }


class FileBehaviorEngine:
    """Ultra-sensitive file behavior monitoring."""
    
    def __init__(self):
        self.activity_buckets = {}  # pid -> FileActivityBucket
        self.thresholds = {
            'alert': {'renames': 10, 'creates': 30, 'bytes': 50*1024*1024},
            'block': {'renames': 30, 'creates': 100, 'bytes': 250*1024*1024},
            'kill': {'renames': 60, 'creates': 200, 'bytes': 500*1024*1024},
        }
        self.sensitivity = 'medium'
    
    def set_sensitivity(self, level):
        """Adjust detection sensitivity."""
        if level == 'high':
            self.thresholds['alert']['renames'] = 10
            self.thresholds['block']['renames'] = 30
        elif level == 'low':
            self.thresholds['alert']['renames'] = 50
            self.thresholds['block']['renames'] = 150
        self.sensitivity = level
    
    def track_file_event(self, pid, process_name, event_type, path, **kwargs):
        """Track individual file event."""
        if pid not in self.activity_buckets:
            self.activity_buckets[pid] = FileActivityBucket(pid, process_name)
        
        bucket = self.activity_buckets[pid]
        
        if event_type == 'created':
            bucket.add_create(path, kwargs.get('size', 0))
        elif event_type == 'renamed':
            bucket.add_rename(path, kwargs.get('dest_path', ''), kwargs.get('size', 0))
        elif event_type == 'deleted':
            bucket.add_delete(path)
        elif event_type == 'written':
            bucket.add_write(path, kwargs.get('bytes', 0))
        elif event_type == 'entropy_check':
            bucket.calculate_entropy(path)
    
    def score_process(self, pid):
        """
        Score process for ransomware behavior (0-100).
        Based on CrowdStrike Threat Graph & SentinelOne AI.
        """
        if pid not in self.activity_buckets:
            return 0
        
        bucket = self.activity_buckets[pid]
        metrics = bucket.get_metrics()
        score = 0
        
        # File rename pattern (most critical indicator)
        if metrics['recent_renames'] > self.thresholds['kill']['renames']:
            score += 40
        elif metrics['recent_renames'] > self.thresholds['block']['renames']:
            score += 25
        elif metrics['recent_renames'] > self.thresholds['alert']['renames']:
            score += 10
        
        # File creation burst
        if metrics['recent_creates'] > self.thresholds['kill']['creates']:
            score += 30
        elif metrics['recent_creates'] > self.thresholds['block']['creates']:
            score += 15
        
        # Byte write volume
        if metrics['recent_bytes'] > self.thresholds['kill']['bytes']:
            score += 20
        elif metrics['recent_bytes'] > self.thresholds['block']['bytes']:
            score += 10
        
        # Suspicious extensions
        if metrics['suspicious_extensions'] > 10:
            score += 25
        elif metrics['suspicious_extensions'] > 5:
            score += 15
        
        # High file entropy (encrypted data)
        if metrics['avg_entropy'] > 7.8:
            score += 20
        elif metrics['avg_entropy'] > 7.5:
            score += 10
        
        return min(score, 100)
    
    def get_threat_level(self, score):
        """Convert score to threat level."""
        if score >= 85:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        elif score >= 25:
            return 'LOW'
        else:
            return 'INFO'
