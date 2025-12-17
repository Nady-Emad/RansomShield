"""
Advanced Monitor Worker
PyQt5 worker thread for real-time ransomware monitoring
Integrates all detection engines for continuous surveillance
"""

import time
from typing import Optional, Dict
from PyQt5.QtCore import QThread, pyqtSignal

from src.engines.file_behavior import FileBehaviorEngine
from src.engines.process_monitor import ProcessMonitorEngine
from src.engines.cli_monitor import CLIMonitorEngine
from src.engines.correlation import CorrelationEngine
from src.engines.response import ResponseEngine, ResponseLevel


class AdvancedMonitorWorker(QThread):
    """
    PyQt5 worker thread for advanced ransomware monitoring
    
    Signals:
        detection_signal: Emitted when ransomware detected (detection_dict)
        alert_signal: Emitted on alerts (alert_dict)
        status_signal: Emitted on status updates (status_dict)
        statistics_signal: Emitted with statistics (stats_dict)
    """
    
    # PyQt5 signals
    detection_signal = pyqtSignal(dict)
    alert_signal = pyqtSignal(dict)
    status_signal = pyqtSignal(dict)
    statistics_signal = pyqtSignal(dict)
    
    def __init__(self, 
                 scan_interval: float = 1.0,
                 auto_response: bool = True,
                 parent=None):
        """
        Initialize Advanced Monitor Worker
        
        Args:
            scan_interval: Time between scans in seconds
            auto_response: Enable automatic threat response
            parent: Parent QObject
        """
        super().__init__(parent)
        
        self.scan_interval = scan_interval
        self.auto_response = auto_response
        self.running = False
        
        # Initialize detection engines
        self.file_engine = FileBehaviorEngine(
            threshold_files_per_second=10,
            entropy_threshold=7.0,
            time_window_seconds=5
        )
        
        self.process_engine = ProcessMonitorEngine(
            cpu_threshold=70.0,
            io_threshold=10_000_000,
            process_spawn_threshold=5,
            monitoring_interval=1.0
        )
        
        self.cli_engine = CLIMonitorEngine(
            critical_threshold=70.0,
            command_rate_threshold=5,
            time_window_seconds=10
        )
        
        self.correlation_engine = CorrelationEngine(
            detection_threshold=70.0,
            correlation_window=30,
            min_signals=2
        )
        
        self.response_engine = ResponseEngine(
            auto_response=auto_response,
            default_level=ResponseLevel.WARN
        )
        
        # Performance metrics
        self.scan_count = 0
        self.detection_count = 0
        self.last_scan_duration = 0.0
        self.start_time = 0.0
        
    def run(self) -> None:
        """Main worker thread loop"""
        self.running = True
        self.start_time = time.time()
        
        self._emit_status({
            'state': 'started',
            'message': 'Advanced monitoring started',
            'timestamp': time.time()
        })
        
        while self.running:
            scan_start = time.time()
            
            try:
                # Perform monitoring cycle
                self._monitoring_cycle()
                
                # Calculate scan duration
                self.last_scan_duration = time.time() - scan_start
                self.scan_count += 1
                
                # Emit statistics periodically
                if self.scan_count % 10 == 0:
                    self._emit_statistics()
                
                # Sleep for remaining interval time
                elapsed = time.time() - scan_start
                if elapsed < self.scan_interval:
                    time.sleep(self.scan_interval - elapsed)
                    
            except Exception as e:
                self._emit_status({
                    'state': 'error',
                    'message': f'Monitoring error: {str(e)}',
                    'timestamp': time.time()
                })
                time.sleep(self.scan_interval)
        
        self._emit_status({
            'state': 'stopped',
            'message': 'Advanced monitoring stopped',
            'timestamp': time.time()
        })
    
    def _monitoring_cycle(self) -> None:
        """Execute one complete monitoring cycle"""
        
        # 1. Scan processes for anomalies
        process_anomaly = self.process_engine.detect_process_anomalies()
        if process_anomaly:
            self._emit_alert(process_anomaly)
            self._add_correlation_signal(
                'process_monitor',
                'process_anomaly',
                process_anomaly.get('average_risk', 0),
                process_anomaly
            )
        
        # 2. Scan command-line activities
        command_anomaly = self.cli_engine.detect_command_anomalies()
        if command_anomaly:
            self._emit_alert(command_anomaly)
            risk_score = command_anomaly.get('average_risk', command_anomaly.get('risk_score', 0))
            self._add_correlation_signal(
                'cli_monitor',
                'command_anomaly',
                risk_score,
                command_anomaly
            )
        
        # 3. Check for mass encryption (file behavior)
        mass_encryption = self.file_engine.detect_mass_encryption()
        if mass_encryption:
            self._emit_alert(mass_encryption)
            self._add_correlation_signal(
                'file_behavior',
                'mass_encryption',
                80.0,  # High risk score
                mass_encryption
            )
        
        # 4. Perform correlation analysis
        detection = self.correlation_engine.detect_ransomware()
        if detection:
            self.detection_count += 1
            self._emit_detection(detection)
            
            # Execute response
            if self.auto_response:
                response = self.response_engine.respond_to_threat(detection)
                self._emit_alert({
                    'type': 'response_executed',
                    'severity': 'info',
                    'response': response,
                    'timestamp': time.time()
                })
        
        # 5. Cleanup dead processes
        self.process_engine.cleanup_dead_processes()
    
    def _add_correlation_signal(self,
                               engine: str,
                               signal_type: str,
                               risk_score: float,
                               metadata: Dict) -> None:
        """Add signal to correlation engine"""
        self.correlation_engine.add_signal(
            engine=engine,
            signal_type=signal_type,
            risk_score=risk_score,
            metadata=metadata
        )
    
    def _emit_detection(self, detection: Dict) -> None:
        """Emit ransomware detection signal"""
        self.detection_signal.emit(detection)
    
    def _emit_alert(self, alert: Dict) -> None:
        """Emit alert signal"""
        self.alert_signal.emit(alert)
    
    def _emit_status(self, status: Dict) -> None:
        """Emit status signal"""
        self.status_signal.emit(status)
    
    def _emit_statistics(self) -> None:
        """Emit comprehensive statistics"""
        uptime = time.time() - self.start_time
        
        stats = {
            'uptime_seconds': uptime,
            'scan_count': self.scan_count,
            'detection_count': self.detection_count,
            'last_scan_duration': self.last_scan_duration,
            'scans_per_second': self.scan_count / uptime if uptime > 0 else 0,
            'file_behavior': self.file_engine.get_statistics(),
            'process_monitor': self.process_engine.get_statistics(),
            'cli_monitor': self.cli_engine.get_statistics(),
            'correlation': self.correlation_engine.get_statistics(),
            'response': self.response_engine.get_statistics(),
            'timestamp': time.time()
        }
        
        self.statistics_signal.emit(stats)
    
    def stop(self) -> None:
        """Stop the monitoring worker"""
        self.running = False
    
    def is_running(self) -> bool:
        """Check if worker is running"""
        return self.running
    
    def get_current_threat_level(self) -> float:
        """Get current composite threat score"""
        score, _ = self.correlation_engine.calculate_composite_score()
        return score
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a specific file
        
        Args:
            file_path: Path to file
            
        Returns:
            Analysis result
        """
        return self.file_engine.analyze_file(file_path)
    
    def analyze_process(self, pid: int) -> Dict:
        """
        Analyze a specific process
        
        Args:
            pid: Process ID
            
        Returns:
            Analysis result
        """
        return self.process_engine.analyze_process(pid)
    
    def analyze_command(self, cmdline: str) -> Dict:
        """
        Analyze a command line
        
        Args:
            cmdline: Command line string
            
        Returns:
            Analysis result
        """
        return self.cli_engine.analyze_command(cmdline)
    
    def set_auto_response(self, enabled: bool) -> None:
        """
        Enable or disable automatic response
        
        Args:
            enabled: True to enable, False to disable
        """
        self.auto_response = enabled
        self.response_engine.auto_response = enabled
    
    def reset_engines(self) -> None:
        """Reset all detection engines"""
        self.file_engine.reset()
        self.process_engine.reset()
        self.cli_engine.reset()
        self.correlation_engine.reset()
        self.response_engine.reset()
        
        self.scan_count = 0
        self.detection_count = 0
        self.last_scan_duration = 0.0
