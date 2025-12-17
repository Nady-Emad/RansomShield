"""
Process Monitor Engine
Monitors process behavior for ransomware indicators:
- Unusual CPU/IO patterns
- Suspicious process names
- Child process spawning
- Memory usage patterns
"""

import psutil
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set
import re


class ProcessMonitorEngine:
    """
    Monitors system processes for ransomware-like behaviors:
    - High CPU usage with file I/O
    - Suspicious process names
    - Rapid process creation
    - Memory anomalies
    """
    
    # Suspicious process name patterns
    SUSPICIOUS_PATTERNS = [
        r'encrypt', r'crypt', r'ransom', r'locker',
        r'vault', r'secure', r'lock', r'wncry',
        r'wannacry', r'petya', r'locky', r'cerber'
    ]
    
    # System processes to ignore
    WHITELIST_PROCESSES = {
        'System', 'svchost.exe', 'csrss.exe', 'smss.exe',
        'explorer.exe', 'dwm.exe', 'services.exe',
        'lsass.exe', 'winlogon.exe'
    }
    
    def __init__(self,
                 cpu_threshold: float = 70.0,
                 io_threshold: int = 10_000_000,  # 10MB/s
                 process_spawn_threshold: int = 5,
                 monitoring_interval: float = 1.0):
        """
        Initialize Process Monitor Engine
        
        Args:
            cpu_threshold: CPU usage % to flag as suspicious
            io_threshold: I/O bytes/sec threshold
            process_spawn_threshold: Max child processes in interval
            monitoring_interval: Monitoring check interval in seconds
        """
        self.cpu_threshold = cpu_threshold
        self.io_threshold = io_threshold
        self.process_spawn_threshold = process_spawn_threshold
        self.monitoring_interval = monitoring_interval
        
        # Process tracking
        self.monitored_processes: Dict[int, Dict] = {}
        self.process_history: deque = deque(maxlen=1000)
        self.suspicious_pids: Set[int] = set()
        
        # Statistics
        self.total_processes_scanned = 0
        self.suspicious_processes_found = 0
        self.alerts: List[Dict] = []
        
        # Cache for process info
        self._process_cache: Dict[int, psutil.Process] = {}
        
    def _get_process(self, pid: int) -> Optional[psutil.Process]:
        """Get process object with caching"""
        if pid not in self._process_cache:
            try:
                self._process_cache[pid] = psutil.Process(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return None
        return self._process_cache.get(pid)
    
    def is_suspicious_name(self, name: str) -> bool:
        """Check if process name matches suspicious patterns"""
        if not name:
            return False
        
        name_lower = name.lower()
        
        # Check whitelist first
        if name in self.WHITELIST_PROCESSES:
            return False
        
        # Check suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, name_lower):
                return True
        
        return False
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """
        Get detailed process information
        
        Args:
            pid: Process ID
            
        Returns:
            Dictionary with process details or None
        """
        try:
            proc = self._get_process(pid)
            if not proc:
                return None
            
            # Get process metrics
            with proc.oneshot():
                info = {
                    'pid': pid,
                    'name': proc.name(),
                    'cpu_percent': proc.cpu_percent(interval=0.1),
                    'memory_mb': proc.memory_info().rss / 1024 / 1024,
                    'num_threads': proc.num_threads(),
                    'create_time': proc.create_time(),
                    'status': proc.status(),
                }
                
                # Get I/O stats if available
                try:
                    io = proc.io_counters()
                    info['io_read_bytes'] = io.read_bytes
                    info['io_write_bytes'] = io.write_bytes
                except (psutil.AccessDenied, AttributeError):
                    info['io_read_bytes'] = 0
                    info['io_write_bytes'] = 0
                
                # Get children
                try:
                    children = proc.children()
                    info['num_children'] = len(children)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    info['num_children'] = 0
            
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def analyze_process(self, pid: int) -> Dict:
        """
        Analyze a process for ransomware indicators
        
        Args:
            pid: Process ID
            
        Returns:
            Analysis results dictionary
        """
        result = {
            'pid': pid,
            'suspicious': False,
            'reasons': [],
            'risk_score': 0.0,
            'info': None
        }
        
        info = self.get_process_info(pid)
        if not info:
            return result
        
        result['info'] = info
        
        # Check process name
        if self.is_suspicious_name(info['name']):
            result['suspicious'] = True
            result['reasons'].append('suspicious_name')
            result['risk_score'] += 50.0
        
        # Check CPU usage
        if info['cpu_percent'] > self.cpu_threshold:
            result['suspicious'] = True
            result['reasons'].append('high_cpu')
            result['risk_score'] += 20.0
        
        # Check I/O activity
        total_io = info['io_read_bytes'] + info['io_write_bytes']
        if pid in self.monitored_processes:
            prev_io = (self.monitored_processes[pid].get('io_read_bytes', 0) +
                      self.monitored_processes[pid].get('io_write_bytes', 0))
            io_rate = (total_io - prev_io) / self.monitoring_interval
            
            if io_rate > self.io_threshold:
                result['suspicious'] = True
                result['reasons'].append('high_io')
                result['risk_score'] += 15.0
        
        # Check child processes
        if info['num_children'] > self.process_spawn_threshold:
            result['suspicious'] = True
            result['reasons'].append('excessive_children')
            result['risk_score'] += 10.0
        
        # Update monitoring
        self.monitored_processes[pid] = info
        
        if result['suspicious']:
            self.suspicious_pids.add(pid)
            self.suspicious_processes_found += 1
        
        return result
    
    def scan_all_processes(self) -> List[Dict]:
        """
        Scan all running processes
        
        Returns:
            List of analysis results for all processes
        """
        results = []
        
        for proc in psutil.process_iter(['pid']):
            try:
                pid = proc.info['pid']
                self.total_processes_scanned += 1
                result = self.analyze_process(pid)
                
                if result['suspicious']:
                    results.append(result)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return results
    
    def detect_process_anomalies(self) -> Optional[Dict]:
        """
        Detect process-based anomalies
        
        Returns:
            Alert dictionary if anomaly detected
        """
        suspicious_results = self.scan_all_processes()
        
        if len(suspicious_results) > 0:
            # Calculate aggregate risk
            total_risk = sum(r['risk_score'] for r in suspicious_results)
            avg_risk = total_risk / len(suspicious_results)
            
            if avg_risk > 50.0:
                alert = {
                    'type': 'process_anomaly',
                    'severity': 'high' if avg_risk > 70 else 'medium',
                    'suspicious_count': len(suspicious_results),
                    'average_risk': avg_risk,
                    'processes': suspicious_results[:5],  # Top 5
                    'timestamp': time.time(),
                    'message': f'{len(suspicious_results)} suspicious processes detected'
                }
                self.alerts.append(alert)
                return alert
        
        return None
    
    def get_process_tree(self, pid: int) -> Dict:
        """
        Get process tree for a given PID
        
        Args:
            pid: Root process ID
            
        Returns:
            Tree structure with process and children
        """
        try:
            proc = self._get_process(pid)
            if not proc:
                return {}
            
            tree = {
                'pid': pid,
                'name': proc.name(),
                'children': []
            }
            
            for child in proc.children(recursive=False):
                tree['children'].append(self.get_process_tree(child.pid))
            
            return tree
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        return {
            'total_processes_scanned': self.total_processes_scanned,
            'suspicious_processes_found': self.suspicious_processes_found,
            'currently_monitored': len(self.monitored_processes),
            'suspicious_pids': len(self.suspicious_pids),
            'alerts_generated': len(self.alerts)
        }
    
    def cleanup_dead_processes(self) -> None:
        """Remove dead processes from monitoring"""
        dead_pids = []
        for pid in self.monitored_processes.keys():
            if not psutil.pid_exists(pid):
                dead_pids.append(pid)
        
        for pid in dead_pids:
            del self.monitored_processes[pid]
            self.suspicious_pids.discard(pid)
            if pid in self._process_cache:
                del self._process_cache[pid]
    
    def reset(self) -> None:
        """Reset engine state"""
        self.monitored_processes.clear()
        self.process_history.clear()
        self.suspicious_pids.clear()
        self.alerts.clear()
        self._process_cache.clear()
        self.total_processes_scanned = 0
        self.suspicious_processes_found = 0
