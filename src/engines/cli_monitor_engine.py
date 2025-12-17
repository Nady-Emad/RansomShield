"""
CLI and backup tamper detection engine.
Detects MITRE T1490 - Inhibit System Recovery attempts.
"""

import psutil
import re
import logging
from collections import deque, defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


class CLIMonitorEngine:
    """Detect backup deletion and system recovery tampering."""
    
    def __init__(self):
        self.backup_kill_patterns = {
            'vssadmin_delete': r'vssadmin.*delete.*shadows',
            'wmic_shadowcopy': r'wmic.*shadowcopy.*delete',
            'bcdedit_recovery': r'bcdedit.*recoveryenabled.*no',
            'wbadmin_delete': r'wbadmin.*delete.*catalog',
            'powershell_vss': r'(Get-WmiObject|Get-CimInstance).*Win32_ShadowCopy',
            'diskpart_clean': r'diskpart.*clean',
            'cipher_delete': r'cipher.*\/w:',
            'fsutil_delete': r'fsutil.*file.*setzerodata',
            'attrib_hidden': r'attrib.*\+h.*\+s',  # Hidden + System attributes
        }
        
        self.detected_commands = deque(maxlen=100)
        self.command_frequency = defaultdict(int)
    
    def check_cli_threat(self):
        """Scan running processes for backup deletion commands."""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    cmdline = " ".join(proc.info.get('cmdline') or []).lower()
                    
                    if not cmdline:
                        continue
                    
                    # Check against patterns
                    for pattern_name, pattern in self.backup_kill_patterns.items():
                        if re.search(pattern, cmdline, re.IGNORECASE):
                            threat = {
                                'timestamp': datetime.now().isoformat(),
                                'pid': pid,
                                'process_name': name,
                                'command': cmdline[:200],
                                'pattern_detected': pattern_name,
                                'severity': 'CRITICAL',
                                'rule': 'BACKUP_TAMPER_ATTEMPT',
                                'message': f'Backup deletion attempt: {pattern_name}'
                            }
                            
                            threats.append(threat)
                            self.detected_commands.append(threat)
                            self.command_frequency[pattern_name] += 1
                            
                            logger.warning(f"🚨 BACKUP TAMPER: {pattern_name} in PID {pid}")
                
                except psutil.NoSuchProcess:
                    continue
        except Exception as e:
            logger.error(f"Error checking CLI threats: {e}")
        
        return threats
    
    def get_threat_level(self):
        """Return threat level based on detected patterns."""
        if len(self.detected_commands) > 0:
            return 'CRITICAL'
        return 'INFO'
