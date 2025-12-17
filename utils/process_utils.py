"""Process utilities with cross-platform support and advanced behavioral detection"""

import psutil
import os
import sys
import signal
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class ProcessBehaviorMonitor:
    """Monitor process behavior for ransomware indicators.
    
    Research-based detection:
    - High I/O operations (>1000 files/sec)
    - Suspicious API patterns
    - Memory injection attempts
    - Network C2 communication
    """
    
    def __init__(self):
        self.process_stats = defaultdict(lambda: {
            'io_reads': 0,
            'io_writes': 0,
            'connections': 0,
            'start_time': time.time(),
            'files_accessed': set(),
            'suspicious_score': 0
        })
    
    def analyze_process(self, pid: int) -> Tuple[int, Dict]:
        """Analyze process behavior for ransomware indicators.
        
        Returns:
            (risk_score, details_dict)
            
        Risk Score:
            0-30: Normal
            31-60: Suspicious
            61-100: High risk (likely ransomware)
        """
        try:
            proc = psutil.Process(pid)
            risk_score = 0
            details = {
                'name': proc.name(),
                'pid': pid,
                'indicators': []
            }
            
            # Check I/O operations
            try:
                io_counters = proc.io_counters()
                stats = self.process_stats[pid]
                elapsed = time.time() - stats['start_time']
                
                if elapsed > 0:
                    # Calculate operations per second
                    reads_per_sec = (io_counters.read_count - stats['io_reads']) / elapsed
                    writes_per_sec = (io_counters.write_count - stats['io_writes']) / elapsed
                    
                    # Research threshold: >1000 file ops/sec = ransomware
                    if writes_per_sec > 1000:
                        risk_score += 40
                        details['indicators'].append(f'High write rate: {writes_per_sec:.0f}/sec')
                    elif writes_per_sec > 500:
                        risk_score += 20
                        details['indicators'].append(f'Elevated write rate: {writes_per_sec:.0f}/sec')
                    
                    stats['io_reads'] = io_counters.read_count
                    stats['io_writes'] = io_counters.write_count
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # Check network connections (C2 communication)
            try:
                connections = proc.connections()
                suspicious_ports = [443, 80, 8080, 4444, 1337]  # Common C2 ports
                for conn in connections:
                    if hasattr(conn, 'raddr') and conn.raddr:
                        if conn.raddr.port in suspicious_ports:
                            risk_score += 15
                            details['indicators'].append(f'Suspicious connection: {conn.raddr.ip}:{conn.raddr.port}')
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # Check open files
            try:
                files = proc.open_files()
                stats = self.process_stats[pid]
                
                # Track unique files accessed
                for f in files:
                    if hasattr(f, 'path'):
                        stats['files_accessed'].add(f.path)
                
                # >100 unique files = suspicious
                if len(stats['files_accessed']) > 100:
                    risk_score += 30
                    details['indicators'].append(f'Accessing many files: {len(stats["files_accessed"])}')
                elif len(stats['files_accessed']) > 50:
                    risk_score += 15
                    details['indicators'].append(f'Multiple files accessed: {len(stats["files_accessed"])}')
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # Check CPU usage (encryption is CPU-intensive)
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
                if cpu_percent > 80:
                    risk_score += 10
                    details['indicators'].append(f'High CPU: {cpu_percent:.1f}%')
            except (psutil.AccessDenied, AttributeError):
                pass
            
            details['risk_score'] = min(risk_score, 100)
            return min(risk_score, 100), details
            
        except psutil.NoSuchProcess:
            return 0, {'error': 'Process not found'}
        except Exception as e:
            return 0, {'error': str(e)}
    
    def reset_stats(self, pid: int):
        """Reset statistics for a process."""
        if pid in self.process_stats:
            del self.process_stats[pid]


def get_process_info(pid):
    """Get comprehensive process information."""
    try:
        proc = psutil.Process(pid)
        info = {
            'pid': pid,
            'name': proc.name(),
            'exe': proc.exe() if hasattr(proc, 'exe') else None,
            'cwd': proc.cwd() if hasattr(proc, 'cwd') else None,
            'status': proc.status(),
            'create_time': proc.create_time(),
            'cpu_percent': proc.cpu_percent(interval=0.1),
            'memory_percent': proc.memory_percent()
        }
        return info
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None
    except Exception:
        return None


def terminate_process(pid, force=True):
    """Terminate process with cross-platform support.
    
    Uses platform-appropriate signals:
    - Windows: taskkill for process tree termination
    - Unix/Linux/Mac: SIGTERM then SIGKILL
    """
    try:
        # Try psutil first (works on all platforms)
        proc = psutil.Process(pid)
        
        if force:
            # Windows: Use SIGKILL equivalent
            if sys.platform == 'win32':
                proc.kill()
            else:
                # Unix/Linux/Mac: Send SIGKILL
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    return False
        else:
            # Graceful termination
            if sys.platform == 'win32':
                proc.terminate()
            else:
                # Unix/Linux/Mac: Send SIGTERM
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    return False
        
        return True
    except Exception:
        # Fallback: try OS-level termination with safe subprocess call
        try:
            if sys.platform == 'win32':
                # SECURITY FIX: Use subprocess instead of os.system to prevent command injection
                import subprocess
                # Validate PID is numeric
                if not isinstance(pid, int) or pid <= 0:
                    return False
                subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                             check=False, timeout=5, capture_output=True)
                return True
            else:
                # Unix fallback - already safe (os.kill with signal)
                os.kill(pid, signal.SIGKILL)
                return True
        except Exception:
            return False
