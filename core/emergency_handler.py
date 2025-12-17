"""Emergency response system - Critical security situation handling.

Features:
- Full system lockdown capability
- Rapid mitigation of high-risk processes
- Emergency event logging
- Lockdown state tracking
- Graceful resumption capability
- Comprehensive error handling

Lockdown Actions:
- Kill all suspicious processes
- Log emergency event
- Track lockdown duration
- Preserve forensic logs
"""

import psutil
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List, Tuple

logger = logging.getLogger(__name__)


class EmergencyHandler:
    """Emergency response and lockdown protocols."""
    
    def __init__(self, config: Dict[str, Any], mitigator: Optional[Any], logger_obj: Optional[Any]):
        """Initialize emergency handler.
        
        Args:
            config: Configuration dict
            mitigator: Mitigator instance for process termination
            logger_obj: Logger instance for event logging
        """
        self.config = config or {}
        self.mitigator = mitigator
        self.logger = logger_obj
        self.lockdown_active = False
        self.lockdown_start: Optional[datetime] = None
    
    def initiate_emergency_lockdown(self, reason: str = "Manual activation") -> bool:
        """Initiate full system lockdown: kill all suspicious processes.
        
        Args:
            reason: Lockdown reason
            
        Returns:
            True if lockdown initiated, False if already active
        """
        try:
            if self.lockdown_active:
                return False
            
            self.lockdown_active = True
            self.lockdown_start = datetime.now()
            
            lockdown_msg = f"EMERGENCY LOCKDOWN INITIATED: {reason}"
            logger.critical(lockdown_msg)
            
            # Log emergency event
            if self.logger:
                self.logger.log_event({
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'CRITICAL',
                    'rule': 'EMERGENCY_LOCKDOWN',
                    'pid': 0,
                    'process_name': 'System',
                    'path': None,
                    'action': 'Lockdown started',
                    'message': reason
                })
            
            # Kill high-risk processes
            killed_count = self._kill_high_risk_processes()
            
            summary = f"Lockdown: terminated {killed_count} high-risk processes"
            logger.critical(summary)
            
            return True
        
        except (TypeError, AttributeError):
            return False
        except Exception:
            return False
    
    def _kill_high_risk_processes(self) -> int:
        """Terminate high-risk processes.
        
        Returns:
            Number of processes killed
        """
        killed_count = 0
        try:
            # Get high-risk processes from config
            high_risk = self.config.get('emergency', {}).get('high_risk_processes', [])
            if not isinstance(high_risk, (list, tuple)):
                high_risk = []
            
            for pid in list(psutil.pids()):
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name().lower() if proc.name() else ''
                    
                    if any(risk.lower() in proc_name for risk in high_risk if isinstance(risk, str)):
                        try:
                            proc.terminate()
                            killed_count += 1
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except (TypeError, ValueError):
            pass
        except Exception:
            pass
        
        return killed_count
        
        try:
            self.logger.log_event({
                'timestamp': datetime.now().isoformat(),
                'severity': 'CRITICAL',
                'rule': 'EMERGENCY_LOCKDOWN',
                'pid': 0,
                'process_name': 'System',
                'path': None,
                'action': 'Lockdown started',
                'message': reason
            })
        except Exception:
            pass
        
        # Kill all highly suspicious processes
        killed_count = self._kill_high_risk_processes()
        
        # Log results
        summary = f"Emergency lockdown: killed {killed_count} high-risk processes"
        logger.critical(summary)
        
        try:
            self.logger.log_event({
                'timestamp': datetime.now().isoformat(),
                'severity': 'CRITICAL',
                'rule': 'LOCKDOWN_SUMMARY',
                'pid': 0,
                'process_name': 'System',
                'path': None,
                'action': 'Lockdown completed',
                'message': summary
            })
        except Exception:
            pass
        
        return True
    
    def _kill_high_risk_processes(self):
        """Kill all processes with suspicion score above kill threshold."""
        killed_count = 0
        kill_threshold = self.config.get('correlation', {}).get('kill_threshold', 120)
        
        # This would need to be populated from MonitorWorker's suspicion dict
        # For now, we kill known ransomware patterns
        ransomware_patterns = [
            'explorer.exe', 'taskhostw.exe', 'winlogon.exe',  # Avoid system processes
        ]
        dangerous_patterns = [
            'conhost.exe', 'powershell.exe', 'cmd.exe',  # Be careful
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pid = proc.pid
                    name = (proc.name() or '').lower()
                    
                    # Skip system processes
                    if name in ['system', 'csrss.exe', 'services.exe', 'lsass.exe', 'svchost.exe']:
                        continue
                    
                    # Skip whitelist
                    if self._is_whitelisted(name):
                        continue
                    
                    # Skip our own process
                    if pid == os.getpid():
                        continue
                    
                    # Kill known patterns (be very conservative)
                    cmdline = " ".join(proc.cmdline() or []).lower() if proc.info.get('cmdline') else ""
                    if any(pat in cmdline for pat in ['vssadmin', 'wmic', 'bcdedit', 'wbadmin']):
                        self.mitigator.terminate_process(pid)
                        killed_count += 1
                        logger.critical(f"Killed suspicious process: {name} (PID {pid})")
                
                except psutil.NoSuchProcess:
                    continue
                except Exception as e:
                    logger.warning(f"Error checking process: {e}")
        
        except Exception as e:
            logger.error(f"Error during lockdown: {e}")
        
        return killed_count
    
    def _is_whitelisted(self, process_name):
        """Check if process is in whitelist."""
        whitelist = self.config.get('whitelist', {}).get('process_names', [])
        return any(process_name.lower() == w.lower() for w in whitelist)
    
    def get_lockdown_status(self):
        """Get current lockdown status."""
        if not self.lockdown_active:
            return {'active': False, 'duration': None}
        
        duration = (datetime.now() - self.lockdown_start).total_seconds()
        return {
            'active': True,
            'started': self.lockdown_start.isoformat(),
            'duration_seconds': duration
        }
    
    def cancel_lockdown(self):
        """Cancel active lockdown (for UI purposes)."""
        if self.lockdown_active:
            self.lockdown_active = False
            logger.warning("Emergency lockdown cancelled")
            return True
        return False
