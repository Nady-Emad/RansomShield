"""System Monitor Engine - Real-time performance metrics collection.

Features:
- Real-time CPU, memory, disk, network metrics
- Per-core performance tracking
- GPU monitoring (if available)
- Top processes by CPU/memory
- Historical metrics with configurable window
- Thread-safe operations
- Comprehensive error handling

Support:
- Windows, Linux, macOS, BSD
- Optional GPU support (NVIDIA via GPUtil)
- CPU temperature monitoring (if available)
"""

import psutil
import platform
from datetime import datetime
from collections import deque
import threading
from typing import Dict, List, Any, Optional, Tuple

try:
    import GPUtil
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False


class SafeSystemAccess:
    """Safe system metric collection with error handling."""
    
    @staticmethod
    def safe_cpu_metrics() -> Dict[str, Any]:
        """Get CPU metrics safely.
        
        Returns:
            Dict with CPU metrics or error indication
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count(logical=False) or 1
            cpu_count_logical = psutil.cpu_count(logical=True) or 1
            per_cpu = psutil.cpu_percent(percpu=True, interval=0.1) or []
            
            # Get frequency safely
            try:
                freq = psutil.cpu_freq()
                cpu_freq = freq.current if freq else 0
            except (AttributeError, OSError):
                cpu_freq = 0
            
            # Get temperature safely
            cpu_temp = 0
            try:
                temps = psutil.sensors_temperatures()
                if temps and 'coretemp' in temps:
                    cpu_temp = temps['coretemp'][0].current if temps['coretemp'] else 0
            except (AttributeError, OSError, IndexError):
                pass
            
            return {
                'overall_percent': cpu_percent,
                'per_core': per_cpu,
                'core_count': cpu_count,
                'logical_cores': cpu_count_logical,
                'frequency': cpu_freq,
                'temperature': cpu_temp,
            }
        
        except (AttributeError, OSError):
            return {'overall_percent': 0, 'error': 'CPU metrics unavailable'}
        except Exception:
            return {'overall_percent': 0}


class SystemMonitor:
    """Collects real-time system performance metrics."""
    
    def __init__(self, history_size=60):
        """Initialize system monitor."""
        self.history_size = history_size
        self.cpu_history = deque(maxlen=history_size)
        self.memory_history = deque(maxlen=history_size)
        self.disk_history = deque(maxlen=history_size)
        self.network_history = deque(maxlen=history_size)
        self.lock = threading.Lock()
        self.network_last = None  # Track last network counters for rate calculation
        
    def get_system_metrics(self):
        """Get comprehensive system metrics."""
        with self.lock:
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu': self.get_cpu_metrics(),
                'memory': self.get_memory_metrics(),
                'disk': self.get_disk_metrics(),
                'network': self.get_network_metrics(),
                'gpu': self.get_gpu_metrics(),
                'top_processes': self.get_top_processes(),
                'platform': platform.system(),
            }
    
    def get_cpu_metrics(self):
        """Get CPU metrics."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count(logical=False)
            cpu_count_logical = psutil.cpu_count(logical=True)
            
            # Per-core usage
            per_cpu = psutil.cpu_percent(percpu=True, interval=0.1)
            
            # CPU frequency
            freq = psutil.cpu_freq()
            cpu_freq = freq.current if freq else 0
            
            # Temperature (if available)
            try:
                temps = psutil.sensors_temperatures()
                cpu_temp = temps.get('coretemp', [{}])[0].get('current', 0) if temps else 0
            except Exception:
                cpu_temp = 0
            
            self.cpu_history.append(cpu_percent)
            
            return {
                'overall_percent': cpu_percent,
                'per_core': per_cpu,
                'core_count': cpu_count,
                'logical_cores': cpu_count_logical,
                'frequency': cpu_freq,
                'temperature': cpu_temp,
                'history': list(self.cpu_history),
            }
        except Exception as e:
            return {'error': str(e), 'overall_percent': 0}
    
    def get_memory_metrics(self):
        """Get memory metrics."""
        try:
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            self.memory_history.append(vm.percent)
            
            return {
                'total': vm.total,
                'available': vm.available,
                'used': vm.used,
                'free': vm.free,
                'percent': vm.percent,
                'active': getattr(vm, 'active', 0),
                'inactive': getattr(vm, 'inactive', 0),
                'buffers': getattr(vm, 'buffers', 0),
                'cached': getattr(vm, 'cached', 0),
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_free': swap.free,
                'swap_percent': swap.percent,
                'history': list(self.memory_history),
            }
        except Exception as e:
            return {'error': str(e), 'percent': 0}
    
    def get_disk_metrics(self):
        """Get disk metrics for all mounted partitions."""
        try:
            metrics = []
            for partition in psutil.disk_partitions():
                if 'cdrom' in partition.opts or partition.fstype == '':
                    continue
                
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    io_counters = psutil.disk_io_counters(perdisk=True)
                    disk_io = io_counters.get(partition.device, None) if io_counters else None
                    
                    metrics.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent,
                        'read_bytes': disk_io.read_bytes if disk_io else 0,
                        'write_bytes': disk_io.write_bytes if disk_io else 0,
                        'read_count': disk_io.read_count if disk_io else 0,
                        'write_count': disk_io.write_count if disk_io else 0,
                    })
                except Exception:
                    continue
            
            # Calculate average disk usage across all partitions for history
            avg_percent = sum(m['percent'] for m in metrics) / len(metrics) if metrics else 0
            self.disk_history.append(avg_percent)
            
            return {
                'partitions': metrics,
                'average_percent': avg_percent,
                'history': list(self.disk_history),
            }
        except Exception as e:
            return {'error': str(e), 'partitions': []}
    
    def get_top_processes(self, limit=10):
        """Get top processes by CPU and memory usage."""
        try:
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_percent'])
                    processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage
            top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:limit]
            
            # Sort by memory usage
            top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:limit]
            
            return {
                'top_cpu': top_cpu,
                'top_memory': top_memory,
            }
        except Exception as e:
            return {'error': str(e), 'top_cpu': [], 'top_memory': []}
    
    def get_network_metrics(self):
        """Get network metrics."""
        try:
            net_io = psutil.net_io_counters()
            
            # Calculate rates if we have previous data
            upload_rate = 0
            download_rate = 0
            
            if self.network_last:
                time_delta = 0.5  # Approximate time between calls
                upload_rate = (net_io.bytes_sent - self.network_last['bytes_sent']) / time_delta
                download_rate = (net_io.bytes_recv - self.network_last['bytes_recv']) / time_delta
            
            # Store current for next calculation
            self.network_last = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
            }
            
            self.network_history.append(download_rate + upload_rate)
            
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'upload_rate': upload_rate,  # Bytes per second
                'download_rate': download_rate,  # Bytes per second
                'total_rate': upload_rate + download_rate,
                'history': list(self.network_history),
            }
        except Exception as e:
            return {'error': str(e), 'upload_rate': 0, 'download_rate': 0}
    
    def get_gpu_metrics(self):
        """Get GPU metrics using GPUtil library."""
        if not GPU_AVAILABLE:
            return {'available': False, 'load': 0, 'temperature': 0}
        
        try:
            gpus = GPUtil.getGPUs()
            if not gpus:
                return {'available': False, 'load': 0, 'temperature': 0}
            
            # Use first GPU
            gpu = gpus[0]
            return {
                'available': True,
                'load': round(gpu.load * 100, 1),  # Convert to percentage
                'temperature': round(gpu.temperature, 1) if gpu.temperature else 0,
                'name': gpu.name,
                'memory_used': round(gpu.memoryUsed / 1024, 1),  # GB
                'memory_total': round(gpu.memoryTotal / 1024, 1),  # GB
                'memory_percent': round((gpu.memoryUsed / gpu.memoryTotal) * 100, 1) if gpu.memoryTotal > 0 else 0
            }
        except Exception as e:
            return {'available': False, 'load': 0, 'temperature': 0}
    
    def get_process_info(self, pid):
        """Get detailed info for specific process."""
        try:
            proc = psutil.Process(pid)
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'status': proc.status(),
                'create_time': proc.create_time(),
                'cpu_percent': proc.cpu_percent(),
                'memory_info': proc.memory_info()._asdict() if proc.memory_info() else {},
                'num_threads': proc.num_threads(),
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'cwd': proc.cwd() if proc.cwd() else '',
                'connections': len(proc.connections()) if proc.connections() else 0,
            }
        except Exception as e:
            return {'error': str(e)}
    
    def format_bytes(self, bytes_val):
        """Format bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"


def calculate_file_entropy(filepath, sample_size=65536):
    """
    Calculate Shannon entropy of a file (safe, atomic operation).

    Args:
        filepath: Path to file
        sample_size: Number of bytes to sample

    Returns:
        float: Entropy value (0-8)
    """
    import math
    from collections import Counter

    try:
        with open(filepath, 'rb') as f:
            # Get file size from same file descriptor (TOCTOU safe)
            f.seek(0, 2)  # Seek to end
            file_size = f.tell()
            f.seek(0)  # Seek back to start

            if file_size == 0:
                return 0.0

            # Read sample
            sample = f.read(min(sample_size, file_size))

            if not sample:
                return 0.0

            # Calculate frequency
            counter = Counter(sample)
            length = len(sample)

            # Calculate Shannon entropy
            entropy = 0.0
            for count in counter.values():
                probability = count / length
                entropy -= probability * math.log2(probability)

            return entropy

    except Exception:
        return 0.0
