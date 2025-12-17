"""Filesystem monitoring core logic - File system event handling.

Features:
- Real-time file system event monitoring
- Modification, creation, deletion, move detection
- Callback-based event handling
- Thread-safe operations
- Error resilience

Support:
- Windows (Win32 API)
- Linux (inotify)
- macOS (FSEvents)
"""

from watchdog.events import FileSystemEventHandler
from typing import Callable, Optional, Dict, Any


class FileMonitorHandler(FileSystemEventHandler):
    """Monitors filesystem changes with error handling."""
    
    def __init__(self, config: Dict[str, Any], on_event_callback: Callable[[Any], None]):
        """Initialize file monitor handler.
        
        Args:
            config: Configuration dict
            on_event_callback: Callback function for file events
        """
        super().__init__()
        self.config = config or {}
        self.on_event_callback = on_event_callback
    
    def on_modified(self, event: Any) -> None:
        """Handle file modification events.
        
        Args:
            event: FileSystemEvent object
        """
        try:
            if not event.is_directory and self.on_event_callback:
                self.on_event_callback(event)
        except (TypeError, AttributeError):
            pass
        except Exception:
            pass
    
    def on_created(self, event: Any) -> None:
        """Handle file creation events.
        
        Args:
            event: FileSystemEvent object
        """
        try:
            if not event.is_directory and self.on_event_callback:
                self.on_event_callback(event)
        except (TypeError, AttributeError):
            pass
        except Exception:
            pass
    
    def on_deleted(self, event: Any) -> None:
        """Handle file deletion events.
        
        Args:
            event: FileSystemEvent object
        """
        try:
            if not event.is_directory and self.on_event_callback:
                self.on_event_callback(event)
        except (TypeError, AttributeError):
            pass
        except Exception:
            pass
    
    def on_moved(self, event: Any) -> None:
        """Handle file move/rename events.
        
        Args:
            event: FileSystemMovedEvent object
        """
        try:
            if not event.is_directory and self.on_event_callback:
                self.on_event_callback(event)
        except (TypeError, AttributeError):
            pass
        except Exception:
            pass
