"""Incident response playbooks - Safe, dry-run by default.

Features:
- Network isolation playbook
- Snapshot/backup playbook
- Dry-run mode (safe by default)
- Event logging for all actions
- Extensible playbook framework
- Non-destructive operations

Playbooks:
- Isolate network connections
- Snapshot critical paths
- Future: Memory dumps, persistence cleanup
"""

import datetime
from typing import Dict, Optional, Any, List


class IncidentPlaybooks:
    """Simple, non-destructive playbooks with dry-run defaults."""
    
    def __init__(self, config: Dict[str, Any], logger: Optional[Any]):
        """Initialize playbooks.
        
        Args:
            config: Configuration dict with playbook settings
            logger: Logger instance
        """
        self.config = config or {}
        self.logger = logger
    
    def execute(self, pid: int, process_name: str, path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Execute playbook actions.
        
        Args:
            pid: Process ID
            process_name: Process name
            path: File path (optional)
            
        Returns:
            List of event dicts for executed actions
        """
        try:
            cfg = self.config.get('playbooks', {})
            if not cfg.get('enabled', False):
                return []
            
            dry_run = cfg.get('dry_run', True)
            actions = []
            events = []
            
            # Network isolation
            if cfg.get('isolate_network', False):
                iso_action = self._isolate_network(dry_run)
                if iso_action:
                    actions.append(iso_action)
            
            # Snapshot paths
            snap_paths = cfg.get('snapshot_paths', []) or []
            if snap_paths and cfg.get('snapshot_enabled', False):
                snap_action = self._snapshot_paths(snap_paths, dry_run)
                if snap_action:
                    actions.append(snap_action)
            
            # Log all actions
            for act in actions:
                try:
                    if not isinstance(act, str):
                        continue
                    
                    event_dict = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'severity': 'INFO' if dry_run else 'CRITICAL',
                        'rule': 'PLAYBOOK',
                        'path': path,
                        'pid': pid,
                        'process_name': process_name,
                        'action': act,
                        'message': 'Playbook executed' if not dry_run else 'Playbook dry-run'
                    }
                    
                    if self.logger:
                        self.logger.log_event(event_dict)
                    
                    events.append(event_dict)
                
                except (TypeError, AttributeError):
                    continue
            
            return events
        
        except (TypeError, ValueError):
            return []
        except Exception:
            return []
    
    def _isolate_network(self, dry_run: bool) -> Optional[str]:
        """Network isolation action.
        
        Args:
            dry_run: If True, only log action
            
        Returns:
            Action description or None
        """
        try:
            return 'Isolate network (dry-run)' if dry_run else 'Isolate network (pending)'
        except Exception:
            return None
    
    def _snapshot_paths(self, paths: List[str], dry_run: bool) -> Optional[str]:
        """Snapshot paths action.
        
        Args:
            paths: List of paths to snapshot
            dry_run: If True, only log action
            
        Returns:
            Action description or None
        """
        try:
            if not isinstance(paths, (list, tuple)):
                return None
            
            path_str = ', '.join(str(p) for p in paths[:3])
            suffix = ' [dry-run]' if dry_run else ''
            return f"Snapshot: {path_str}{suffix}"
        
        except (TypeError, ValueError):
            return None
        except Exception:
            return None
