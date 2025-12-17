"""Admin privilege checking utility."""
import sys
import os


def is_admin():
    """Check if running with admin/root privileges."""
    try:
        if sys.platform == 'win32':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Unix/Linux/Mac
            return os.geteuid() == 0
    except Exception:
        return False


def require_admin():
    """Check admin and raise if not running as admin."""
    if not is_admin():
        raise PermissionError(
            "This application requires administrator/root privileges.\n"
            "Please run as Administrator (Windows) or with sudo (Linux/Mac)."
        )
