"""Process Termination Module - Safe process killing with logging.

Features:
- Safe process termination with graceful shutdown
- SIGTERM fallback to SIGKILL on timeout
- Cross-platform support (Windows, Linux, macOS)
- Comprehensive error handling
- Event logging for all operations
- Process state validation

Flow:
1. Validate process exists
2. Get process info (name, exe, cmdline)
3. Log termination intent
4. Attempt graceful terminate() - 3 second timeout
5. On timeout, use SIGKILL (Unix) or taskkill /F (Windows)
6. Log result and status
"""

import psutil
import os
import sys
from datetime import datetime
from typing import Dict, Optional, Any, Tuple


class ProcessTerminator:
    """Handles safe termination of malicious processes."""
    
    def __init__(self, logger: Optional[Any]):
        """Initialize process terminator.
        
        Args:
            logger: Logger instance for event logging
        """
        self.logger = logger
    
    def terminate_process(self, pid: int, reason: str) -> Dict[str, Any]:
        """Terminate a process safely.
        
        Args:
            pid: Process ID
            reason: Termination reason
        
        Returns:
            Dict with termination result and status
        """
        try:
            if not isinstance(pid, int) or pid < 1:
                return {'success': False, 'error': 'Invalid PID'}
            
            # Check if process exists
            if not psutil.pid_exists(pid):
                return {'success': False, 'error': 'Process not found'}
            
            # Get process info
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name() or 'Unknown'
                try:
                    proc_exe = proc.exe()
                except (psutil.AccessDenied, OSError):
                    proc_exe = 'Unknown'
                
                try:
                    proc_cmdline = ' '.join(proc.cmdline())
                except (psutil.AccessDenied, OSError):
                    proc_cmdline = 'Unknown'
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                return {'success': False, 'error': f'Cannot access process: {str(e)[:40]}'}
            
            # Log termination intent
            if self.logger:
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'WARNING',
                    'rule': 'PROCESS_TERMINATION',
                    'message': f'Terminating PID {pid} ({proc_name}): {reason}'
                })
            
            # Try graceful termination
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    # Graceful failed, use kill
                    proc.kill()
                    if self.logger:
                        self.logger.log_event({
                            'timestamp': datetime.now().isoformat(),
                            'severity': 'WARNING',
                            'rule': 'PROCESS_KILL',
                            'message': f'Force killed PID {pid}'
                        })
                
                return {'success': True, 'status': 'Process terminated'}
            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return {'success': False, 'error': 'Cannot terminate process'}
        
        except (TypeError, ValueError):
            return {'success': False, 'error': 'Invalid parameters'}
        except Exception:
            return {'success': False, 'error': 'Termination failed'}
            
            # Log intent
            self.logger.log_event({
                'timestamp': datetime.now().isoformat(),
                'severity': 'WARNING',
                'rule': 'PROCESS_TERMINATION',
                'message': f'Attempting to terminate PID {pid} ({proc_name}): {reason}'
            })
            
            # Try graceful termination first
            try:
                proc.terminate()
                
                # Wait up to 3 seconds for graceful exit
                proc.wait(timeout=3)
                
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'INFO',
                    'rule': 'PROCESS_TERMINATED',
                    'message': f'Process {pid} ({proc_name}) terminated gracefully'
                })
                
                return {
                    'success': True,
                    'method': 'graceful',
                    'pid': pid,
                    'name': proc_name
                }
            
            except psutil.TimeoutExpired:
                # Force kill
                proc.kill()
                
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'WARNING',
                    'rule': 'PROCESS_KILLED',
                    'message': f'Process {pid} ({proc_name}) force killed'
                })
                
                return {
                    'success': True,
                    'method': 'force',
                    'pid': pid,
                    'name': proc_name
                }
        
        except Exception as e:
            self.logger.log_event({
                'timestamp': datetime.now().isoformat(),
                'severity': 'ERROR',
                'rule': 'TERMINATION_ERROR',
                'message': f'Failed to terminate PID {pid}: {str(e)}'
            })
            
            return {'success': False, 'error': str(e)}
    
    def terminate_by_name(self, process_name, reason):
        """
        Terminate all processes matching a name.
        
        Args:
            process_name: Process name to match
            reason: Termination reason
        
        Returns:
            dict: Summary of terminations
        """
        terminated = []
        failed = []
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    result = self.terminate_process(proc.info['pid'], reason)
                    
                    if result['success']:
                        terminated.append(proc.info['pid'])
                    else:
                        failed.append(proc.info['pid'])
            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return {
            'terminated': terminated,
            'failed': failed,
            'total': len(terminated) + len(failed)
        }
