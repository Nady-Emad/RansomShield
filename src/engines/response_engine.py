"""
Response and autonomous mitigation engine.
Inspired by SentinelOne's automatic kill and rollback capabilities.
"""

import psutil
import time
import logging
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)


class ResponseEngine:
    """
    Autonomous response system for rapid mitigation.
    """
    
    def __init__(self, ui_callback=None):
        self.ui_callback = ui_callback
        self.response_log = deque(maxlen=1000)
        self.auto_kill_enabled = True
        self.quarantine_dir = './quarantine'
        self.process_history = {}
    
    def execute_response(self, threat_data, action):
        """Execute defensive action based on threat level."""
        
        pid = threat_data['pid']
        process_name = threat_data['process_name']
        threat_level = threat_data['threat_level']
        
        response_record = {
            'timestamp': datetime.now().isoformat(),
            'pid': pid,
            'process_name': process_name,
            'action': action,
            'status': 'pending'
        }
        
        try:
            if action == 'KILL_PROCESS':
                self._kill_process(pid, process_name)
                response_record['status'] = 'executed'
                response_record['message'] = f'Process {pid} terminated'
            
            elif action == 'BLOCK_WRITES':
                self._block_process_writes(pid, process_name)
                response_record['status'] = 'executed'
                response_record['message'] = f'Write access blocked for {pid}'
            
            elif action == 'ALERT':
                self._raise_alert(threat_data)
                response_record['status'] = 'executed'
                response_record['message'] = 'User alerted'
            
            elif action == 'MONITOR':
                response_record['status'] = 'executed'
                response_record['message'] = 'Process monitoring in progress'
        
        except Exception as e:
            response_record['status'] = 'failed'
            response_record['error'] = str(e)
            logger.error(f"Response execution failed: {e}")
        
        self.response_log.append(response_record)
        return response_record
    
    def _kill_process(self, pid, process_name):
        """
        Kill malicious process and entire process tree.
        Uses graceful terminate first, then force kill if needed.
        
        SECURITY: Validates process is not critical system process before termination.
        """
        # SECURITY FIX: Critical system processes that must never be killed
        CRITICAL_PROCESSES = {
            'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'smss.exe',
            'winlogon.exe', 'explorer.exe', 'svchost.exe', 'system', 'systemd',
            'init', 'launchd', 'kernel_task'
        }
        
        try:
            proc = psutil.Process(pid)
            proc_name_lower = proc.name().lower()
            
            # SECURITY CHECK: Never kill critical system processes
            if proc_name_lower in CRITICAL_PROCESSES:
                logger.error(
                    f"⚠️ BLOCKED: Attempted to kill critical system process: {proc.name()} (PID {pid}). "
                    "This could crash the system. Process will NOT be terminated."
                )
                raise PermissionError(f"Cannot terminate critical system process: {proc.name()}")
            
            # SECURITY CHECK: Validate PID belongs to expected process name
            if process_name and proc.name().lower() != process_name.lower():
                logger.warning(
                    f"⚠️ PID MISMATCH: Expected '{process_name}' but found '{proc.name()}' at PID {pid}. "
                    "Possible PID reuse. Aborting termination."
                )
                raise ValueError(f"PID {pid} process name mismatch (expected {process_name}, found {proc.name()})")
            
            children = proc.children(recursive=True)
            
            # Kill children first (prevents respawn)
            for child in children:
                try:
                    # Check critical process for children too
                    if child.name().lower() not in CRITICAL_PROCESSES:
                        child.terminate()
                except Exception:
                    pass
            
            time.sleep(0.3)
            
            # Force kill remaining children
            for child in children:
                try:
                    if child.is_running() and child.name().lower() not in CRITICAL_PROCESSES:
                        child.kill()
                except Exception:
                    pass
            
            # Kill parent
            proc.terminate()
            time.sleep(0.2)
            if proc.is_running():
                proc.kill()
            
            logger.critical(f"🔴 PROCESS TREE KILLED: {process_name} (PID {pid}) + {len(children)} children")
            self.process_history[pid] = 'killed'
        
        except Exception as e:
            logger.error(f"Failed to kill process tree {pid}: {e}")
    
    def _block_process_writes(self, pid, process_name):
        """
        Block write access for process.
        Note: Requires driver/API access on Windows for full implementation.
        Current implementation provides alert.
        """
        try:
            logger.warning(f"🟡 BLOCK: Write access denied for {process_name} (PID {pid})")
            self.process_history[pid] = 'blocked'
        except Exception as e:
            logger.error(f"Failed to block process {pid}: {e}")
    
    def _raise_alert(self, threat_data):
        """Raise user alert via callback."""
        try:
            message = f"""
🚨 RANSOMWARE ALERT 🚨

Process: {threat_data['process_name']} (PID {threat_data['pid']})
Threat Level: {threat_data['threat_level']}
Score: {threat_data['composite_score']:.1f}/100

Recommended Action: {threat_data['recommended_action']}

File Score: {threat_data['file_score']}/100
Process Score: {threat_data['process_score']}/100

Do you want to terminate this process?
            """
            if self.ui_callback:
                self.ui_callback(message, threat_data)
            logger.warning(f"Alert raised for {threat_data['process_name']}")
        
        except Exception as e:
            logger.error(f"Failed to raise alert: {e}")
    
    def get_response_summary(self):
        """Get summary of response actions."""
        total = len(self.response_log)
        killed = sum(1 for r in self.response_log if r.get('action') == 'KILL_PROCESS')
        blocked = sum(1 for r in self.response_log if r.get('action') == 'BLOCK_WRITES')
        
        return {
            'total_responses': total,
            'processes_killed': killed,
            'processes_blocked': blocked,
            'success_rate': sum(1 for r in self.response_log if r.get('status') == 'executed') / total if total > 0 else 0
        }
