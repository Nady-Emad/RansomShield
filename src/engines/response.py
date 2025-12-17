"""
Response Engine
Autonomous response system for ransomware threats:
- Process termination
- Network isolation
- File quarantine
- System alerts
"""

import os
import time
import psutil
from typing import Dict, List, Optional, Set, Callable
from enum import Enum


class ResponseAction(Enum):
    """Response action types"""
    ALERT = "alert"
    PROCESS_TERMINATE = "process_terminate"
    PROCESS_SUSPEND = "process_suspend"
    NETWORK_ISOLATE = "network_isolate"
    FILE_QUARANTINE = "file_quarantine"
    SNAPSHOT_CREATE = "snapshot_create"
    USER_NOTIFY = "user_notify"


class ResponseLevel(Enum):
    """Response severity levels"""
    MONITOR = 1  # Just monitor and log
    WARN = 2     # Warn user
    CONTAIN = 3  # Contain threat (suspend process)
    TERMINATE = 4  # Terminate threat (kill process)


class ResponseEngine:
    """
    Autonomous response engine for ransomware threats:
    - Configurable response actions
    - Process termination/suspension
    - Alert generation
    - Response logging
    """
    
    def __init__(self, 
                 auto_response: bool = True,
                 default_level: ResponseLevel = ResponseLevel.WARN,
                 termination_timeout: float = 3.0):
        """
        Initialize Response Engine
        
        Args:
            auto_response: Enable automatic responses
            default_level: Default response level
            termination_timeout: Timeout in seconds for graceful process termination
        """
        self.auto_response = auto_response
        self.default_level = default_level
        self.termination_timeout = termination_timeout
        
        # Response tracking
        self.actions_taken: List[Dict] = []
        self.terminated_processes: Set[int] = set()
        self.suspended_processes: Set[int] = set()
        self.quarantined_files: Set[str] = set()
        
        # Response callbacks
        self.callbacks: Dict[ResponseAction, List[Callable]] = {
            action: [] for action in ResponseAction
        }
        
        # Statistics
        self.total_responses = 0
        self.successful_responses = 0
        self.failed_responses = 0
        
    def register_callback(self, 
                         action: ResponseAction, 
                         callback: Callable) -> None:
        """
        Register a callback for response actions
        
        Args:
            action: Response action type
            callback: Callback function
        """
        if action in self.callbacks:
            self.callbacks[action].append(callback)
    
    def determine_response_level(self, 
                                threat_score: float,
                                severity: str) -> ResponseLevel:
        """
        Determine appropriate response level
        
        Args:
            threat_score: Composite threat score (0-100)
            severity: Threat severity (low, medium, high, critical)
            
        Returns:
            ResponseLevel
        """
        if not self.auto_response:
            return ResponseLevel.MONITOR
        
        if severity == 'critical' or threat_score >= 85:
            return ResponseLevel.TERMINATE
        elif severity == 'high' or threat_score >= 70:
            return ResponseLevel.CONTAIN
        elif severity == 'medium' or threat_score >= 50:
            return ResponseLevel.WARN
        else:
            return ResponseLevel.MONITOR
    
    def respond_to_threat(self, 
                         threat: Dict,
                         custom_level: Optional[ResponseLevel] = None) -> Dict:
        """
        Execute response to detected threat
        
        Args:
            threat: Threat detection dictionary
            custom_level: Override automatic level determination
            
        Returns:
            Response result dictionary
        """
        response = {
            'threat': threat,
            'actions': [],
            'success': True,
            'timestamp': time.time(),
            'message': ''
        }
        
        # Determine response level
        level = custom_level or self.determine_response_level(
            threat.get('composite_score', 0),
            threat.get('severity', 'low')
        )
        
        response['level'] = level.name
        
        # Execute actions based on level
        if level == ResponseLevel.MONITOR:
            action_result = self._log_threat(threat)
            response['actions'].append(action_result)
            
        elif level == ResponseLevel.WARN:
            action_result = self._generate_alert(threat)
            response['actions'].append(action_result)
            action_result = self._notify_user(threat)
            response['actions'].append(action_result)
            
        elif level == ResponseLevel.CONTAIN:
            action_result = self._generate_alert(threat)
            response['actions'].append(action_result)
            
            # Suspend suspicious processes
            if 'processes' in threat.get('breakdown', {}):
                for proc_info in threat['breakdown'].get('processes', []):
                    if 'pid' in proc_info:
                        action_result = self._suspend_process(proc_info['pid'])
                        response['actions'].append(action_result)
            
        elif level == ResponseLevel.TERMINATE:
            action_result = self._generate_alert(threat)
            response['actions'].append(action_result)
            
            # Terminate suspicious processes
            if 'processes' in threat.get('breakdown', {}):
                for proc_info in threat['breakdown'].get('processes', []):
                    if 'pid' in proc_info:
                        action_result = self._terminate_process(proc_info['pid'])
                        response['actions'].append(action_result)
        
        # Check if any action failed
        response['success'] = all(a.get('success', False) for a in response['actions'])
        
        # Update statistics
        self.total_responses += 1
        if response['success']:
            self.successful_responses += 1
        else:
            self.failed_responses += 1
        
        # Store response
        self.actions_taken.append(response)
        
        return response
    
    def _log_threat(self, threat: Dict) -> Dict:
        """Log threat for monitoring"""
        result = {
            'action': ResponseAction.ALERT.value,
            'success': True,
            'message': f"Threat logged: {threat.get('type', 'unknown')}"
        }
        
        # Execute callbacks
        for callback in self.callbacks.get(ResponseAction.ALERT, []):
            try:
                callback(threat)
            except Exception as e:
                result['success'] = False
                result['error'] = str(e)
        
        return result
    
    def _generate_alert(self, threat: Dict) -> Dict:
        """Generate alert for threat"""
        result = {
            'action': ResponseAction.ALERT.value,
            'success': True,
            'severity': threat.get('severity', 'unknown'),
            'message': threat.get('message', 'Threat detected')
        }
        
        # Execute callbacks
        for callback in self.callbacks.get(ResponseAction.ALERT, []):
            try:
                callback(threat)
            except Exception as e:
                result['success'] = False
                result['error'] = str(e)
        
        return result
    
    def _notify_user(self, threat: Dict) -> Dict:
        """Notify user of threat"""
        result = {
            'action': ResponseAction.USER_NOTIFY.value,
            'success': True,
            'message': f"User notified: {threat.get('message', 'Threat detected')}"
        }
        
        # Execute callbacks
        for callback in self.callbacks.get(ResponseAction.USER_NOTIFY, []):
            try:
                callback(threat)
            except Exception as e:
                result['success'] = False
                result['error'] = str(e)
        
        return result
    
    def _suspend_process(self, pid: int) -> Dict:
        """
        Suspend a process
        
        Args:
            pid: Process ID
            
        Returns:
            Action result
        """
        result = {
            'action': ResponseAction.PROCESS_SUSPEND.value,
            'pid': pid,
            'success': False,
            'message': ''
        }
        
        try:
            if not psutil.pid_exists(pid):
                result['message'] = f"Process {pid} does not exist"
                return result
            
            proc = psutil.Process(pid)
            proc.suspend()
            
            self.suspended_processes.add(pid)
            result['success'] = True
            result['message'] = f"Process {pid} ({proc.name()}) suspended"
            
            # Execute callbacks
            for callback in self.callbacks.get(ResponseAction.PROCESS_SUSPEND, []):
                callback({'pid': pid, 'name': proc.name()})
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            result['message'] = f"Failed to suspend process {pid}: {str(e)}"
        
        return result
    
    def _terminate_process(self, pid: int) -> Dict:
        """
        Terminate a process
        
        Args:
            pid: Process ID
            
        Returns:
            Action result
        """
        result = {
            'action': ResponseAction.PROCESS_TERMINATE.value,
            'pid': pid,
            'success': False,
            'message': ''
        }
        
        try:
            if not psutil.pid_exists(pid):
                result['message'] = f"Process {pid} does not exist"
                return result
            
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            # Try graceful termination first
            proc.terminate()
            
            # Wait for process to terminate
            try:
                proc.wait(timeout=self.termination_timeout)
            except psutil.TimeoutExpired:
                # Force kill if still running
                proc.kill()
            
            self.terminated_processes.add(pid)
            result['success'] = True
            result['message'] = f"Process {pid} ({proc_name}) terminated"
            
            # Execute callbacks
            for callback in self.callbacks.get(ResponseAction.PROCESS_TERMINATE, []):
                callback({'pid': pid, 'name': proc_name})
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            result['message'] = f"Failed to terminate process {pid}: {str(e)}"
        
        return result
    
    def resume_process(self, pid: int) -> bool:
        """
        Resume a suspended process
        
        Args:
            pid: Process ID
            
        Returns:
            True if successful
        """
        try:
            if pid not in self.suspended_processes:
                return False
            
            if not psutil.pid_exists(pid):
                self.suspended_processes.discard(pid)
                return False
            
            proc = psutil.Process(pid)
            proc.resume()
            self.suspended_processes.discard(pid)
            return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def get_statistics(self) -> Dict:
        """Get response engine statistics"""
        return {
            'total_responses': self.total_responses,
            'successful_responses': self.successful_responses,
            'failed_responses': self.failed_responses,
            'terminated_processes': len(self.terminated_processes),
            'suspended_processes': len(self.suspended_processes),
            'quarantined_files': len(self.quarantined_files),
            'auto_response_enabled': self.auto_response
        }
    
    def get_recent_actions(self, limit: int = 10) -> List[Dict]:
        """
        Get recent response actions
        
        Args:
            limit: Number of actions to return
            
        Returns:
            List of recent actions
        """
        return self.actions_taken[-limit:]
    
    def reset(self) -> None:
        """Reset engine state"""
        # Resume all suspended processes
        for pid in list(self.suspended_processes):
            self.resume_process(pid)
        
        self.actions_taken.clear()
        self.terminated_processes.clear()
        self.suspended_processes.clear()
        self.quarantined_files.clear()
        self.total_responses = 0
        self.successful_responses = 0
        self.failed_responses = 0
