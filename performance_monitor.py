"""
Performance Monitoring Module
Real-time system metrics collection using psutil
"""

import threading
import time
from datetime import datetime

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. Performance monitoring will show placeholder data.")
    print("Install with: pip install psutil")


class PerformanceMonitor:
    """Collect and monitor system performance metrics"""
    
    def __init__(self, update_callback=None):
        self.update_callback = update_callback
        self.monitoring = False
        self.monitor_thread = None
    
    def start(self):
        """Start background monitoring thread"""
        if not PSUTIL_AVAILABLE or self.monitoring:
            return False
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        return True
    
    def stop(self):
        """Stop monitoring"""
        self.monitoring = False
    
    def _monitor_loop(self):
        """Background loop to collect performance data"""
        while self.monitoring:
            try:
                # Collect CPU, Memory, Disk data
                cpu_pct = psutil.cpu_percent(interval=0.5)
                mem = psutil.virtual_memory()
                partitions = psutil.disk_partitions()
                mountpoint = partitions[0].mountpoint if partitions else '/'
                disk = psutil.disk_usage(mountpoint)
                
                # CPU details
                cpu_freq = psutil.cpu_freq()
                cpu_details = {
                    'cores': f"{psutil.cpu_count(logical=False)} cores ({psutil.cpu_count()} logical)",
                    'freq': f"{cpu_freq.current / 1000:.2f} GHz" if cpu_freq else "N/A",
                    'temp': 'N/A'  # Temperature requires platform-specific sensors
                }
                
                # Memory details
                mem_details = {
                    'total': f"{mem.total / (1024**3):.1f} GB",
                    'used': f"{mem.used / (1024**3):.1f} GB",
                    'available': f"{mem.available / (1024**3):.1f} GB"
                }
                
                # Disk details
                disk_details = {
                    'total': f"{disk.total / (1024**3):.0f} GB",
                    'used': f"{disk.used / (1024**3):.0f} GB",
                    'free': f"{disk.free / (1024**3):.0f} GB"
                }
                
                # Top processes
                processes = []
                for proc in psutil.process_iter(['name', 'pid', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append({
                            'name': proc.info['name'],
                            'pid': proc.info['pid'],
                            'cpu': proc.info['cpu_percent'] or 0,
                            'mem': proc.info['memory_percent'] or 0
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                top_cpu = sorted(processes, key=lambda x: x['cpu'], reverse=True)[:10]
                top_mem = sorted(processes, key=lambda x: x['mem'], reverse=True)[:10]
                
                # Call update callback
                if self.update_callback:
                    self.update_callback(
                        cpu_pct=int(cpu_pct),
                        mem_pct=int(mem.percent),
                        disk_pct=int(disk.percent),
                        tasks=len(processes),
                        cpu_details=cpu_details,
                        mem_details=mem_details,
                        disk_details=disk_details,
                        top_cpu_processes=top_cpu,
                        top_mem_processes=top_mem
                    )
                
            except Exception as e:
                print(f"Performance monitoring error: {e}")
            
            # Update every 2 seconds
            time.sleep(2)
    
    @staticmethod
    def is_available():
        """Check if psutil is available"""
        return PSUTIL_AVAILABLE
