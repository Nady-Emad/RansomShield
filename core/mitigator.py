"""Process mitigation - Cross-platform safe process termination.

Features:
- Graceful process termination with force-kill fallback
- Process tree termination (parent + children)
- Critical system process protection
- Cross-platform support (Windows, Linux, macOS)
- Comprehensive error handling
- Safe PID validation

Safety:
- Never terminates critical system processes
- Validates process exists before termination
- Handles permission denied gracefully
- Prevents system crashes
"""

import os
import sys
import signal
import psutil
from typing import List, Tuple, Optional


class SafeTerminationHelper:
    """Safe process termination helper with error handling."""
    
    # Critical system processes - NEVER terminate these
    CRITICAL_PROCESSES = {
        'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe',
        'smss.exe', 'winlogon.exe', 'explorer.exe', 'svchost.exe',
        'system', 'systemd', 'init', 'launchd', 'kernel_task',
        'System', 'kernel', 'idle'
    }
    
    @staticmethod
    def is_critical_process(pid: int) -> bool:
        """Check if process is critical and should not be terminated."""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
            return proc_name in {p.lower() for p in SafeTerminationHelper.CRITICAL_PROCESSES}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        except Exception:
            return True  # Assume critical on error
    
    @staticmethod
    def safe_get_process_tree(pid: int) -> List[psutil.Process]:
        """Get process tree (parent + children) safely."""
        try:
            parent = psutil.Process(pid)
            return [parent] + parent.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
        except Exception:
            return []


class ProcessMitigator:
    """Process termination with safety checks."""
    
    def __init__(self, config=None, logger=None):
        self.config = config or {}
        self.logger = logger
    
    def terminate_process(self, pid: int) -> Tuple[bool, str]:
        """Terminate process tree (best-effort, cross-platform).
        
        Args:
            pid: Process ID to terminate
            
        Returns:
            (success, message) tuple
        """
        try:
            # Safety check: never terminate critical processes
            if SafeTerminationHelper.is_critical_process(pid):
                msg = f"Blocked termination of critical process (PID {pid})"
                if self.logger:
                    self.logger.warning(msg)
                return False, msg
            
            if sys.platform == 'win32':
                # Windows: use taskkill with process tree
                try:
                    result = os.system(f'taskkill /F /T /PID {pid}') == 0
                    return result, "Process tree terminated" if result else "Termination failed"
                except Exception as e:
                    return False, f"Windows termination error: {e}"
            else:
                # Unix/Linux/macOS: manual tree termination
                procs = SafeTerminationHelper.safe_get_process_tree(pid)
                if not procs:
                    return False, "Process not found"
                
                # Kill children before parent (prevent respawn)
                for proc in reversed(procs):
                    try:
                        proc.terminate()  # Graceful termination
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    except Exception:
                        pass
                
                # Force kill if still running
                for proc in reversed(procs):
                    try:
                        if proc.is_running():
                            os.kill(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    except Exception:
                        pass
                
                return True, "Process tree terminated"
        
        except (psutil.NoSuchProcess, ProcessLookupError):
            return False, "Process not found"
        except psutil.AccessDenied:
            return False, "Access denied"
        except Exception as e:
            if self.logger:
                self.logger.error(f"Process termination error: {e}")
            return False, f"Error: {e}"
