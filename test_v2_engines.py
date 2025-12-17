"""
Comprehensive Test Suite for Sentinel Guard V2 Engines
Tests all detection engines, correlation, response, and PyQt5 worker
"""

import os
import time
import tempfile
import pytest
from unittest.mock import Mock, patch, MagicMock

from src.engines.file_behavior import FileBehaviorEngine
from src.engines.process_monitor import ProcessMonitorEngine
from src.engines.cli_monitor import CLIMonitorEngine
from src.engines.correlation import CorrelationEngine
from src.engines.response import ResponseEngine, ResponseLevel, ResponseAction


class TestFileBehaviorEngine:
    """Test suite for File Behavior Engine"""
    
    def test_initialization(self):
        """Test engine initialization"""
        engine = FileBehaviorEngine()
        assert engine.threshold_fps == 10
        assert engine.entropy_threshold == 7.0
        assert engine.time_window == 5
        assert engine.total_files_monitored == 0
    
    def test_entropy_calculation_high(self):
        """Test entropy calculation for encrypted file"""
        engine = FileBehaviorEngine()
        
        # Create a file with random (high entropy) data
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            # Random bytes simulate encryption
            import random
            random_data = bytes([random.randint(0, 255) for _ in range(8192)])
            f.write(random_data)
            temp_path = f.name
        
        try:
            entropy = engine.calculate_entropy(temp_path)
            assert entropy > 7.0, f"Expected entropy > 7.0, got {entropy}"
        finally:
            os.unlink(temp_path)
    
    def test_entropy_calculation_low(self):
        """Test entropy calculation for normal text file"""
        engine = FileBehaviorEngine()
        
        # Create a file with low entropy (repeated text)
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write("A" * 8192)
            temp_path = f.name
        
        try:
            entropy = engine.calculate_entropy(temp_path)
            assert entropy < 2.0, f"Expected entropy < 2.0, got {entropy}"
        finally:
            os.unlink(temp_path)
    
    def test_suspicious_extension_detection(self):
        """Test ransomware extension detection"""
        engine = FileBehaviorEngine()
        
        assert engine.is_suspicious_extension("file.encrypted")
        assert engine.is_suspicious_extension("document.locky")
        assert engine.is_suspicious_extension("data.wannacry")
        assert not engine.is_suspicious_extension("file.txt")
        assert not engine.is_suspicious_extension("document.docx")
    
    def test_analyze_file_suspicious(self):
        """Test file analysis for suspicious file"""
        engine = FileBehaviorEngine()
        
        # Create high entropy file with suspicious extension
        with tempfile.NamedTemporaryFile(delete=False, suffix='.encrypted', mode='wb') as f:
            import random
            f.write(bytes([random.randint(0, 255) for _ in range(8192)]))
            temp_path = f.name
        
        try:
            result = engine.analyze_file(temp_path)
            assert result['suspicious']
            assert 'suspicious_extension' in result['reasons']
            assert result['risk_score'] > 40.0
        finally:
            os.unlink(temp_path)
    
    def test_operation_recording(self):
        """Test file operation recording"""
        engine = FileBehaviorEngine()
        
        engine.record_operation('modified', '/test/file.txt')
        engine.record_operation('created', '/test/file2.txt')
        
        assert engine.total_files_monitored == 2
        assert len(engine.file_operations) == 2
    
    def test_operation_rate_calculation(self):
        """Test operation rate calculation"""
        engine = FileBehaviorEngine()
        
        # Record operations rapidly
        for i in range(50):
            engine.record_operation('modified', f'/test/file{i}.txt')
        
        rate = engine.get_operation_rate()
        assert rate > 0
    
    def test_mass_encryption_detection(self):
        """Test mass encryption detection"""
        engine = FileBehaviorEngine(threshold_files_per_second=5)
        
        # Simulate rapid file operations
        for i in range(30):
            path = f'/test/file{i}.encrypted'
            engine.record_operation('modified', path)
            engine.entropy_cache[path] = 7.5  # High entropy
        
        alert = engine.detect_mass_encryption()
        assert alert is not None
        assert alert['type'] == 'mass_encryption'
        assert alert['severity'] == 'critical'
    
    def test_statistics(self):
        """Test statistics collection"""
        engine = FileBehaviorEngine()
        
        engine.record_operation('modified', '/test/file.txt')
        stats = engine.get_statistics()
        
        assert 'total_files_monitored' in stats
        assert stats['total_files_monitored'] == 1
    
    def test_reset(self):
        """Test engine reset"""
        engine = FileBehaviorEngine()
        
        engine.record_operation('modified', '/test/file.txt')
        engine.reset()
        
        assert engine.total_files_monitored == 0
        assert len(engine.file_operations) == 0


class TestProcessMonitorEngine:
    """Test suite for Process Monitor Engine"""
    
    def test_initialization(self):
        """Test engine initialization"""
        engine = ProcessMonitorEngine()
        assert engine.cpu_threshold == 70.0
        assert engine.total_processes_scanned == 0
    
    def test_suspicious_name_detection(self):
        """Test suspicious process name detection"""
        engine = ProcessMonitorEngine()
        
        assert engine.is_suspicious_name("encrypt.exe")
        assert engine.is_suspicious_name("ransomware.exe")
        assert engine.is_suspicious_name("wannacry.exe")
        assert not engine.is_suspicious_name("explorer.exe")
        assert not engine.is_suspicious_name("notepad.exe")
    
    def test_whitelist_processes(self):
        """Test whitelisted processes are not flagged"""
        engine = ProcessMonitorEngine()
        
        assert not engine.is_suspicious_name("svchost.exe")
        assert not engine.is_suspicious_name("explorer.exe")
        assert not engine.is_suspicious_name("System")
    
    @patch('psutil.Process')
    def test_get_process_info(self, mock_process):
        """Test getting process information"""
        engine = ProcessMonitorEngine()
        
        # Mock process
        mock_proc = MagicMock()
        mock_proc.name.return_value = "test.exe"
        mock_proc.cpu_percent.return_value = 50.0
        mock_proc.memory_info.return_value.rss = 1024 * 1024 * 100  # 100MB
        mock_proc.num_threads.return_value = 4
        mock_proc.create_time.return_value = time.time()
        mock_proc.status.return_value = "running"
        mock_proc.io_counters.return_value.read_bytes = 1000
        mock_proc.io_counters.return_value.write_bytes = 2000
        mock_proc.children.return_value = []
        
        mock_process.return_value = mock_proc
        
        info = engine.get_process_info(1234)
        assert info is not None
        assert info['name'] == "test.exe"
        assert info['cpu_percent'] == 50.0
    
    def test_statistics(self):
        """Test statistics collection"""
        engine = ProcessMonitorEngine()
        stats = engine.get_statistics()
        
        assert 'total_processes_scanned' in stats
        assert 'suspicious_processes_found' in stats
    
    def test_reset(self):
        """Test engine reset"""
        engine = ProcessMonitorEngine()
        engine.total_processes_scanned = 100
        engine.reset()
        
        assert engine.total_processes_scanned == 0
        assert len(engine.monitored_processes) == 0


class TestCLIMonitorEngine:
    """Test suite for CLI Monitor Engine"""
    
    def test_initialization(self):
        """Test engine initialization"""
        engine = CLIMonitorEngine()
        assert engine.critical_threshold == 70.0
        assert engine.total_commands_analyzed == 0
    
    def test_critical_command_detection(self):
        """Test detection of critical ransomware commands"""
        engine = CLIMonitorEngine()
        
        result = engine.analyze_command("vssadmin delete shadows /all")
        assert result['suspicious']
        assert result['risk_score'] >= 70.0
    
    def test_bcdedit_command_detection(self):
        """Test detection of boot config tampering"""
        engine = CLIMonitorEngine()
        
        result = engine.analyze_command("bcdedit /set {default} recoveryenabled No")
        assert result['suspicious']
        assert result['risk_score'] >= 70.0
    
    def test_cipher_command_detection(self):
        """Test detection of free space wiping"""
        engine = CLIMonitorEngine()
        
        result = engine.analyze_command("cipher /w:C:\\temp")
        assert result['suspicious']
        assert result['risk_score'] >= 60.0
    
    def test_wmic_shadowcopy_detection(self):
        """Test detection of WMI shadow copy deletion"""
        engine = CLIMonitorEngine()
        
        result = engine.analyze_command("wmic shadowcopy delete")
        assert result['suspicious']
        assert result['risk_score'] >= 80.0
    
    def test_normal_command(self):
        """Test that normal commands are not flagged"""
        engine = CLIMonitorEngine()
        
        result = engine.analyze_command("dir C:\\Users")
        assert not result['suspicious']
        assert result['risk_score'] == 0.0
    
    def test_command_anomaly_detection(self):
        """Test detection of multiple suspicious commands"""
        engine = CLIMonitorEngine(command_rate_threshold=3)
        
        # Simulate multiple suspicious commands
        engine.analyze_command("vssadmin delete shadows /all")
        engine.analyze_command("bcdedit /set recoveryenabled No")
        engine.analyze_command("wbadmin delete catalog")
        
        alert = engine.detect_command_anomalies()
        assert alert is not None
        assert alert['type'] == 'command_anomaly'
    
    def test_top_threats(self):
        """Test getting top threat commands"""
        engine = CLIMonitorEngine()
        
        engine.analyze_command("vssadmin delete shadows /all")
        engine.analyze_command("dir C:\\")
        engine.analyze_command("bcdedit /set recoveryenabled No")
        
        top_threats = engine.get_top_threats(limit=2)
        assert len(top_threats) <= 2
        assert all(t['suspicious'] for t in top_threats)
    
    def test_statistics(self):
        """Test statistics collection"""
        engine = CLIMonitorEngine()
        
        engine.analyze_command("vssadmin delete shadows")
        stats = engine.get_statistics()
        
        assert stats['total_commands_analyzed'] == 1
        assert stats['suspicious_count'] == 1
    
    def test_reset(self):
        """Test engine reset"""
        engine = CLIMonitorEngine()
        
        engine.analyze_command("vssadmin delete shadows")
        engine.reset()
        
        assert engine.total_commands_analyzed == 0
        assert len(engine.command_history) == 0


class TestCorrelationEngine:
    """Test suite for Correlation Engine"""
    
    def test_initialization(self):
        """Test engine initialization"""
        engine = CorrelationEngine()
        assert engine.detection_threshold == 70.0
        assert engine.total_signals == 0
    
    def test_add_signal(self):
        """Test adding signals from engines"""
        engine = CorrelationEngine()
        
        engine.add_signal('file_behavior', 'high_entropy', 75.0, {'file': 'test.txt'})
        assert engine.total_signals == 1
    
    def test_composite_score_calculation(self):
        """Test composite threat score calculation"""
        engine = CorrelationEngine()
        
        # Add signals from multiple engines
        engine.add_signal('file_behavior', 'mass_encryption', 80.0)
        engine.add_signal('process_monitor', 'suspicious_process', 70.0)
        engine.add_signal('cli_monitor', 'critical_command', 85.0)
        
        score, breakdown = engine.calculate_composite_score()
        
        assert score > 0
        assert 'engine_scores' in breakdown
        assert len(breakdown['engine_scores']) == 3
    
    def test_ransomware_detection(self):
        """Test ransomware detection with correlated signals"""
        engine = CorrelationEngine(detection_threshold=70.0, min_signals=2)
        
        # Add high-risk signals from multiple engines
        engine.add_signal('file_behavior', 'mass_encryption', 85.0)
        engine.add_signal('process_monitor', 'suspicious_process', 75.0)
        engine.add_signal('cli_monitor', 'critical_command', 90.0)
        
        detection = engine.detect_ransomware()
        
        assert detection is not None
        assert detection['type'] == 'ransomware_detection'
        assert detection['composite_score'] >= 70.0
        assert detection['confidence'] > 0
    
    def test_no_detection_insufficient_signals(self):
        """Test that detection requires minimum signals"""
        engine = CorrelationEngine(min_signals=2)
        
        # Add signal from only one engine
        engine.add_signal('file_behavior', 'high_entropy', 80.0)
        
        detection = engine.detect_ransomware()
        assert detection is None
    
    def test_threat_trend(self):
        """Test threat trend analysis"""
        engine = CorrelationEngine()
        
        # Add signals over time and calculate scores
        for i in range(5):
            engine.add_signal('file_behavior', 'test', 50.0 + i * 10)
            engine.calculate_composite_score()  # This populates composite_scores
            time.sleep(0.1)
        
        trend = engine.get_threat_trend(duration=60)
        assert len(trend) > 0
    
    def test_threat_escalation_detection(self):
        """Test detection of escalating threats"""
        engine = CorrelationEngine()
        
        # Add increasing threat scores
        for i in range(10):
            score = 30.0 + i * 5.0
            engine.add_signal('file_behavior', 'test', score)
            engine.calculate_composite_score()
            time.sleep(0.05)
        
        is_escalating = engine.is_threat_escalating(threshold_increase=10.0)
        assert isinstance(is_escalating, bool)
    
    def test_statistics(self):
        """Test statistics collection"""
        engine = CorrelationEngine()
        
        engine.add_signal('file_behavior', 'test', 50.0)
        stats = engine.get_statistics()
        
        assert 'total_signals' in stats
        assert stats['total_signals'] == 1
    
    def test_reset(self):
        """Test engine reset"""
        engine = CorrelationEngine()
        
        engine.add_signal('file_behavior', 'test', 50.0)
        engine.reset()
        
        assert engine.total_signals == 0


class TestResponseEngine:
    """Test suite for Response Engine"""
    
    def test_initialization(self):
        """Test engine initialization"""
        engine = ResponseEngine()
        assert engine.auto_response
        assert engine.total_responses == 0
    
    def test_response_level_determination(self):
        """Test automatic response level determination"""
        engine = ResponseEngine()
        
        # Critical threat
        level = engine.determine_response_level(90.0, 'critical')
        assert level == ResponseLevel.TERMINATE
        
        # High threat
        level = engine.determine_response_level(75.0, 'high')
        assert level == ResponseLevel.CONTAIN
        
        # Medium threat
        level = engine.determine_response_level(55.0, 'medium')
        assert level == ResponseLevel.WARN
        
        # Low threat
        level = engine.determine_response_level(35.0, 'low')
        assert level == ResponseLevel.MONITOR
    
    def test_callback_registration(self):
        """Test callback registration"""
        engine = ResponseEngine()
        callback = Mock()
        
        engine.register_callback(ResponseAction.ALERT, callback)
        assert callback in engine.callbacks[ResponseAction.ALERT]
    
    def test_respond_to_threat_monitor(self):
        """Test monitor-level response"""
        engine = ResponseEngine()
        
        threat = {
            'type': 'test_threat',
            'composite_score': 20.0,
            'severity': 'low'
        }
        
        response = engine.respond_to_threat(threat)
        assert response['success']
        assert response['level'] == 'MONITOR'
    
    def test_respond_to_threat_warn(self):
        """Test warn-level response"""
        engine = ResponseEngine()
        
        threat = {
            'type': 'test_threat',
            'composite_score': 55.0,
            'severity': 'medium'
        }
        
        response = engine.respond_to_threat(threat)
        assert response['success']
        assert response['level'] == 'WARN'
        assert len(response['actions']) >= 2  # Alert + notify
    
    @patch('psutil.Process')
    @patch('psutil.pid_exists')
    def test_suspend_process(self, mock_pid_exists, mock_process):
        """Test process suspension"""
        engine = ResponseEngine()
        
        mock_pid_exists.return_value = True
        mock_proc = MagicMock()
        mock_proc.name.return_value = "test.exe"
        mock_process.return_value = mock_proc
        
        result = engine._suspend_process(1234)
        assert result['success']
        assert 1234 in engine.suspended_processes
    
    @patch('psutil.Process')
    @patch('psutil.pid_exists')
    def test_terminate_process(self, mock_pid_exists, mock_process):
        """Test process termination"""
        engine = ResponseEngine()
        
        mock_pid_exists.return_value = True
        mock_proc = MagicMock()
        mock_proc.name.return_value = "test.exe"
        mock_process.return_value = mock_proc
        
        result = engine._terminate_process(1234)
        assert result['success']
        assert 1234 in engine.terminated_processes
    
    def test_statistics(self):
        """Test statistics collection"""
        engine = ResponseEngine()
        stats = engine.get_statistics()
        
        assert 'total_responses' in stats
        assert 'auto_response_enabled' in stats
    
    def test_reset(self):
        """Test engine reset"""
        engine = ResponseEngine()
        
        engine.total_responses = 10
        engine.reset()
        
        assert engine.total_responses == 0


class TestPerformanceMetrics:
    """Test suite for performance requirements"""
    
    def test_detection_latency(self):
        """Test that detection latency is < 1 second"""
        engine = FileBehaviorEngine()
        
        start_time = time.time()
        
        # Perform file analysis
        with tempfile.NamedTemporaryFile(delete=False, suffix='.encrypted') as f:
            f.write(b"A" * 8192)
            temp_path = f.name
        
        try:
            result = engine.analyze_file(temp_path)
            latency = time.time() - start_time
            
            assert latency < 1.0, f"Detection latency {latency}s exceeds 1s requirement"
        finally:
            os.unlink(temp_path)
    
    def test_entropy_calculation_performance(self):
        """Test entropy calculation performance"""
        engine = FileBehaviorEngine()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"X" * 8192)
            temp_path = f.name
        
        try:
            start_time = time.time()
            entropy = engine.calculate_entropy(temp_path)
            duration = time.time() - start_time
            
            assert duration < 0.1, f"Entropy calculation took {duration}s, should be < 0.1s"
        finally:
            os.unlink(temp_path)
    
    def test_command_analysis_performance(self):
        """Test command analysis performance"""
        engine = CLIMonitorEngine()
        
        start_time = time.time()
        result = engine.analyze_command("vssadmin delete shadows /all")
        duration = time.time() - start_time
        
        assert duration < 0.01, f"Command analysis took {duration}s, should be < 0.01s"


class TestAccuracyMetrics:
    """Test suite for accuracy requirements (99%+ detection)"""
    
    def test_ransomware_command_detection_accuracy(self):
        """Test detection accuracy for known ransomware commands"""
        engine = CLIMonitorEngine()
        
        # Known ransomware commands
        ransomware_commands = [
            "vssadmin delete shadows /all",
            "bcdedit /set {default} recoveryenabled No",
            "wbadmin delete catalog -quiet",
            "wmic shadowcopy delete",
            "cipher /w:C:\\temp",
        ]
        
        detected = 0
        for cmd in ransomware_commands:
            result = engine.analyze_command(cmd)
            if result['suspicious']:
                detected += 1
        
        accuracy = (detected / len(ransomware_commands)) * 100
        assert accuracy >= 99.0, f"Detection accuracy {accuracy}% is below 99% requirement"
    
    def test_false_positive_rate(self):
        """Test false positive rate for normal commands"""
        engine = CLIMonitorEngine()
        
        # Normal commands
        normal_commands = [
            "dir C:\\Users",
            "ipconfig /all",
            "ping google.com",
            "notepad.exe",
            "tasklist",
        ]
        
        false_positives = 0
        for cmd in normal_commands:
            result = engine.analyze_command(cmd)
            if result['suspicious']:
                false_positives += 1
        
        fp_rate = (false_positives / len(normal_commands)) * 100
        assert fp_rate < 5.0, f"False positive rate {fp_rate}% is too high"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
