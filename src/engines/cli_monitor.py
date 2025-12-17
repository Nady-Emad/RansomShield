"""
CLI Monitor Engine
Monitors command-line activities for ransomware indicators:
- Suspicious commands (vssadmin, bcdedit, cipher)
- Shadow copy deletion
- Boot configuration changes
- File deletion commands
"""

import psutil
import re
import time
from collections import deque
from typing import Dict, List, Optional, Set


class CLIMonitorEngine:
    """
    Monitors command-line interface for ransomware behaviors:
    - Shadow copy deletion (vssadmin delete shadows)
    - Boot config tampering (bcdedit)
    - Mass file operations
    - System recovery disabling
    """
    
    # Highly suspicious commands used by ransomware
    CRITICAL_COMMANDS = {
        'vssadmin delete shadows': 80.0,  # Delete shadow copies
        'vssadmin.exe delete shadows': 80.0,
        'bcdedit /set': 70.0,  # Modify boot config
        'bcdedit.exe /set': 70.0,
        'wbadmin delete': 75.0,  # Delete backups
        'wbadmin.exe delete': 75.0,
        'wmic shadowcopy delete': 80.0,  # Delete shadow copies via WMI
        'cipher /w': 60.0,  # Wipe free space
        'cipher.exe /w': 60.0,
    }
    
    # Suspicious command patterns
    SUSPICIOUS_PATTERNS = [
        (r'vssadmin.*delete', 80.0),
        (r'bcdedit.*(bootstatuspolicy|recoveryenabled)', 70.0),
        (r'wbadmin.*delete.*backup', 75.0),
        (r'wmic.*shadowcopy.*delete', 80.0),
        (r'cipher\s+/w', 60.0),
        (r'reg.*delete.*System.*CurrentControlSet', 65.0),
        (r'schtasks.*/create.*/ru\s+system', 50.0),  # Create scheduled task as system
        (r'powershell.*-enc.*', 55.0),  # Encoded PowerShell
        (r'cmd.*/c.*del.*/s.*/q', 45.0),  # Recursive delete
        (r'net\s+stop.*vss', 70.0),  # Stop VSS service
    ]
    
    # Command keywords to monitor
    MONITORED_KEYWORDS = {
        'vssadmin', 'bcdedit', 'wbadmin', 'cipher',
        'wmic', 'shadowcopy', 'backup', 'recovery',
        'bootstatuspolicy', 'delete', 'format'
    }
    
    def __init__(self, 
                 critical_threshold: float = 70.0,
                 command_rate_threshold: int = 5,
                 time_window_seconds: int = 10):
        """
        Initialize CLI Monitor Engine
        
        Args:
            critical_threshold: Risk score to trigger alert
            command_rate_threshold: Max suspicious commands in time window
            time_window_seconds: Time window for rate calculation
        """
        self.critical_threshold = critical_threshold
        self.command_rate_threshold = command_rate_threshold
        self.time_window = time_window_seconds
        
        # Command tracking
        self.command_history: deque = deque(maxlen=1000)
        self.suspicious_commands: List[Dict] = []
        
        # Statistics
        self.total_commands_analyzed = 0
        self.suspicious_count = 0
        self.critical_count = 0
        self.alerts: List[Dict] = []
        
    def analyze_command(self, cmdline: str, pid: int = 0) -> Dict:
        """
        Analyze a command line for ransomware indicators
        
        Args:
            cmdline: Command line string
            pid: Process ID (optional)
            
        Returns:
            Analysis result dictionary
        """
        result = {
            'command': cmdline,
            'pid': pid,
            'suspicious': False,
            'reasons': [],
            'risk_score': 0.0,
            'timestamp': time.time()
        }
        
        if not cmdline:
            return result
        
        cmdline_lower = cmdline.lower().strip()
        
        # Check critical commands
        for cmd, score in self.CRITICAL_COMMANDS.items():
            if cmd.lower() in cmdline_lower:
                result['suspicious'] = True
                result['reasons'].append(f'critical_command: {cmd}')
                result['risk_score'] = max(result['risk_score'], score)
        
        # Check suspicious patterns
        for pattern, score in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmdline_lower):
                result['suspicious'] = True
                result['reasons'].append(f'pattern_match: {pattern}')
                result['risk_score'] = max(result['risk_score'], score)
        
        # Check for monitored keywords
        for keyword in self.MONITORED_KEYWORDS:
            if keyword in cmdline_lower:
                if not result['suspicious']:
                    result['reasons'].append(f'keyword: {keyword}')
                    result['risk_score'] = max(result['risk_score'], 30.0)
        
        self.total_commands_analyzed += 1
        
        if result['suspicious']:
            self.suspicious_count += 1
            self.suspicious_commands.append(result)
            
            if result['risk_score'] >= self.critical_threshold:
                self.critical_count += 1
        
        # Record in history
        self.command_history.append(result)
        
        return result
    
    def scan_running_processes(self) -> List[Dict]:
        """
        Scan command lines of all running processes
        
        Returns:
            List of analysis results for suspicious processes
        """
        results = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if cmdline:
                    # Join command line arguments
                    cmdline_str = ' '.join(cmdline)
                    result = self.analyze_command(cmdline_str, proc.info['pid'])
                    
                    if result['suspicious']:
                        results.append(result)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return results
    
    def detect_command_anomalies(self) -> Optional[Dict]:
        """
        Detect anomalous command patterns
        
        Returns:
            Alert dictionary if anomaly detected
        """
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        # Get recent suspicious commands
        recent_suspicious = [
            cmd for cmd in self.command_history
            if cmd['suspicious'] and cmd['timestamp'] >= cutoff_time
        ]
        
        if len(recent_suspicious) >= self.command_rate_threshold:
            # Calculate average risk
            avg_risk = sum(cmd['risk_score'] for cmd in recent_suspicious) / len(recent_suspicious)
            
            alert = {
                'type': 'command_anomaly',
                'severity': 'critical' if avg_risk >= 70 else 'high',
                'command_count': len(recent_suspicious),
                'average_risk': avg_risk,
                'commands': recent_suspicious[:5],  # Top 5
                'timestamp': current_time,
                'message': f'{len(recent_suspicious)} suspicious commands in {self.time_window}s'
            }
            self.alerts.append(alert)
            return alert
        
        # Check for single critical command
        critical_commands = [
            cmd for cmd in recent_suspicious
            if cmd['risk_score'] >= self.critical_threshold
        ]
        
        if critical_commands:
            alert = {
                'type': 'critical_command',
                'severity': 'critical',
                'command': critical_commands[0]['command'],
                'risk_score': critical_commands[0]['risk_score'],
                'reasons': critical_commands[0]['reasons'],
                'timestamp': current_time,
                'message': f'Critical command detected: {critical_commands[0]["command"][:100]}'
            }
            self.alerts.append(alert)
            return alert
        
        return None
    
    def get_command_statistics(self) -> Dict:
        """Get command analysis statistics"""
        current_time = time.time()
        cutoff_time = current_time - 60  # Last minute
        
        recent_commands = [
            cmd for cmd in self.command_history
            if cmd['timestamp'] >= cutoff_time
        ]
        
        return {
            'total_analyzed': self.total_commands_analyzed,
            'suspicious_count': self.suspicious_count,
            'critical_count': self.critical_count,
            'recent_commands': len(recent_commands),
            'alerts_generated': len(self.alerts)
        }
    
    def get_top_threats(self, limit: int = 10) -> List[Dict]:
        """
        Get top threat commands by risk score
        
        Args:
            limit: Number of results to return
            
        Returns:
            List of top threat commands
        """
        sorted_commands = sorted(
            self.suspicious_commands,
            key=lambda x: x['risk_score'],
            reverse=True
        )
        return sorted_commands[:limit]
    
    def is_command_suspicious(self, cmdline: str) -> bool:
        """
        Quick check if command is suspicious
        
        Args:
            cmdline: Command line string
            
        Returns:
            True if suspicious, False otherwise
        """
        result = self.analyze_command(cmdline)
        return result['suspicious']
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        return {
            'total_commands_analyzed': self.total_commands_analyzed,
            'suspicious_count': self.suspicious_count,
            'critical_count': self.critical_count,
            'alerts_generated': len(self.alerts),
            'command_history_size': len(self.command_history)
        }
    
    def reset(self) -> None:
        """Reset engine state"""
        self.command_history.clear()
        self.suspicious_commands.clear()
        self.alerts.clear()
        self.total_commands_analyzed = 0
        self.suspicious_count = 0
        self.critical_count = 0
