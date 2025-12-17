"""
CPU and process activity monitoring engine.
Detects I/O spikes and anomalous CPU usage patterns.
"""

import psutil
import time
import logging
from collections import deque

logger = logging.getLogger(__name__)


class ProcessActivityMetrics:
    """Track per-process CPU and I/O metrics."""
    
    def __init__(self, pid, process_name):
        self.pid = pid
        self.process_name = process_name
        self.creation_time = time.time()
        
        # CPU metrics
        self.cpu_samples = deque(maxlen=60)
        self.peak_cpu = 0
        self.avg_cpu = 0
        
        # I/O metrics
        self.io_samples = deque(maxlen=60)
        self.total_writes = 0
        self.total_reads = 0
        self.prev_writes = 0
        self.prev_reads = 0
        
        # Process metadata
        self.open_files_count = 0
        self.threads_count = 0
        self.memory_mb = 0
    
    def add_sample(self, cpu_percent, io_bytes_written, io_bytes_read):
        """Add CPU/IO sample."""
        self.cpu_samples.append(cpu_percent)
        self.io_samples.append(io_bytes_written)
        
        self.peak_cpu = max(self.peak_cpu, cpu_percent)
        self.avg_cpu = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0
        
        # Track delta
        write_delta = io_bytes_written - self.prev_writes
        read_delta = io_bytes_read - self.prev_reads
        
        if write_delta > 0:
            self.total_writes += write_delta
        if read_delta > 0:
            self.total_reads += read_delta
        
        self.prev_writes = io_bytes_written
        self.prev_reads = io_bytes_read


class ProcessMonitorEngine:
    """Monitor CPU, I/O, and process behavior for ransomware indicators."""
    
    def __init__(self):
        self.process_metrics = {}  # pid -> ProcessActivityMetrics
        self.whitelist_processes = {
            'explorer.exe', 'svchost.exe', 'dwm.exe', 'taskhostw.exe',
            'SearchIndexer.exe', 'WindowsUpdate.exe', 'wuauclt.exe',
            'python.exe', 'node.exe', 'docker.exe', 'system', 'services.exe',
            'csrss.exe', 'lsass.exe', 'conhost.exe', 'notepad.exe'
        }
    
    def update_process_stats(self):
        """Sample all running processes."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'io_counters']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    
                    # Skip whitelisted processes
                    if name.lower() in self.whitelist_processes:
                        continue
                    
                    if pid not in self.process_metrics:
                        self.process_metrics[pid] = ProcessActivityMetrics(pid, name)
                    
                    metrics = self.process_metrics[pid]
                    
                    # Update CPU
                    cpu = proc.info['cpu_percent'] or 0
                    
                    # Update I/O
                    io = proc.info.get('io_counters')
                    write_bytes = io.write_bytes if io else 0
                    read_bytes = io.read_bytes if io else 0
                    
                    metrics.add_sample(cpu, write_bytes, read_bytes)
                
                except psutil.NoSuchProcess:
                    continue
        except Exception as e:
            logger.error(f"Error sampling processes: {e}")
    
    def score_process_activity(self, pid):
        """Score process for suspicious CPU/IO patterns."""
        if pid not in self.process_metrics:
            return 0
        
        metrics = self.process_metrics[pid]
        score = 0
        
        # CPU spike (sustained high CPU)
        if metrics.avg_cpu > 50:
            score += 15
        if metrics.peak_cpu > 80:
            score += 10
        
        # I/O spike (rapid disk writes)
        if metrics.total_writes > 500*1024*1024:  # > 500MB
            score += 20
        elif metrics.total_writes > 100*1024*1024:  # > 100MB
            score += 10
        
        # Process age (new processes more suspicious)
        age_seconds = time.time() - metrics.creation_time
        if age_seconds < 5:
            score += 15
        elif age_seconds < 60:
            score += 5
        
        return min(score, 100)
