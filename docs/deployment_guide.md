# Deployment Guide - Sentinel Guard

Complete guide for deploying RansomShield Sentinel Guard in production environments.

## Table of Contents
1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Setup](#service-setup)
6. [Monitoring & Logging](#monitoring--logging)
7. [Performance Tuning](#performance-tuning)
8. [Security Hardening](#security-hardening)
9. [Troubleshooting](#troubleshooting)
10. [Maintenance](#maintenance)

---

## Pre-Deployment Checklist

Before deploying to production:

- [ ] System requirements verified
- [ ] Python 3.8+ installed
- [ ] Administrator privileges confirmed
- [ ] Backup system in place
- [ ] Test environment validated
- [ ] Rollback plan prepared
- [ ] Monitoring infrastructure ready
- [ ] Alert recipients configured
- [ ] Documentation reviewed
- [ ] Team trained on operation

## System Requirements

### Minimum Requirements
- **OS**: Windows 10 (1809+) or Windows 11
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Disk**: 500 MB free space
- **Permissions**: Administrator privileges

### Recommended for Production
- **OS**: Windows 10/11 (latest updates)
- **CPU**: 4 cores, 3.0 GHz
- **RAM**: 8 GB
- **Disk**: 2 GB free space (for logs)
- **Network**: Stable connection for updates
- **Backup**: System restore points enabled

### Software Dependencies
- Python 3.8, 3.9, 3.10, or 3.11
- pip (Python package manager)
- Windows Defender or compatible AV (configured to allow)

## Installation

### 1. Create Deployment Directory
```powershell
# Create installation directory
New-Item -Path "C:\Program Files\RansomShield" -ItemType Directory -Force

# Set permissions
icacls "C:\Program Files\RansomShield" /grant:r "Administrators:(OI)(CI)F"
```

### 2. Install Python
```powershell
# Download Python 3.11 (recommended)
# Use silent install for automation
python-3.11.0-amd64.exe /quiet InstallAllUsers=1 PrependPath=1
```

### 3. Deploy Application
```powershell
# Navigate to installation directory
cd "C:\Program Files\RansomShield"

# Clone repository (or copy files)
git clone https://github.com/Nady-Emad/RansomShield.git .

# Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Verify Installation
```powershell
# Run test suite
python -m pytest test_v2_engines.py -v

# Check all engines load
python -c "from src.engines import *; print('All engines loaded successfully')"
```

## Configuration

### 1. Create Configuration File
Create `config.py` in the root directory:

```python
# config.py - Production Configuration

# File Behavior Engine
FILE_BEHAVIOR_CONFIG = {
    'threshold_files_per_second': 15,  # Adjust based on environment
    'entropy_threshold': 7.0,
    'time_window_seconds': 5
}

# Process Monitor Engine
PROCESS_MONITOR_CONFIG = {
    'cpu_threshold': 75.0,  # Higher for busy servers
    'io_threshold': 20_000_000,  # 20 MB/s
    'process_spawn_threshold': 10,
    'monitoring_interval': 2.0
}

# CLI Monitor Engine
CLI_MONITOR_CONFIG = {
    'critical_threshold': 70.0,
    'command_rate_threshold': 3,
    'time_window_seconds': 10
}

# Correlation Engine
CORRELATION_CONFIG = {
    'detection_threshold': 75.0,  # Higher threshold for production
    'correlation_window': 30,
    'min_signals': 2
}

# Response Engine
RESPONSE_CONFIG = {
    'auto_response': True,  # Set to False for alert-only mode
    'default_level': 'WARN'  # MONITOR, WARN, CONTAIN, or TERMINATE
}

# Logging
LOGGING_CONFIG = {
    'log_level': 'INFO',
    'log_file': 'C:\\ProgramData\\RansomShield\\logs\\sentinel.log',
    'max_log_size_mb': 100,
    'backup_count': 5
}

# Alerting
ALERT_CONFIG = {
    'email_enabled': True,
    'email_recipients': ['security@company.com'],
    'smtp_server': 'smtp.company.com',
    'smtp_port': 587,
    'webhook_url': 'https://company.com/webhooks/ransomshield'
}

# Performance
PERFORMANCE_CONFIG = {
    'scan_interval': 2.0,  # Seconds between scans
    'max_worker_threads': 4,
    'enable_performance_monitoring': True
}
```

### 2. Configure Logging
Create logging setup in `setup_logging.py`:

```python
# setup_logging.py
import logging
import logging.handlers
from pathlib import Path

def setup_logging(config):
    """Setup production logging"""
    
    # Create log directory
    log_file = Path(config['log_file'])
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, config['log_level']))
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=config['max_log_size_mb'] * 1024 * 1024,
        backupCount=config['backup_count']
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(file_handler)
    
    # Console handler for errors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(logging.Formatter(
        '%(levelname)s: %(message)s'
    ))
    logger.addHandler(console_handler)
    
    return logger
```

### 3. Create Main Service Script
Create `service.py`:

```python
# service.py - Main service entry point
import time
import logging
from config import *
from setup_logging import setup_logging
from src.engines import *
from workers import AdvancedMonitorWorker

# Setup logging
logger = setup_logging(LOGGING_CONFIG)

def main():
    """Main service loop"""
    logger.info("Starting Sentinel Guard service...")
    
    try:
        # Initialize engines with config
        file_engine = FileBehaviorEngine(**FILE_BEHAVIOR_CONFIG)
        process_engine = ProcessMonitorEngine(**PROCESS_MONITOR_CONFIG)
        cli_engine = CLIMonitorEngine(**CLI_MONITOR_CONFIG)
        correlation_engine = CorrelationEngine(**CORRELATION_CONFIG)
        response_engine = ResponseEngine(
            auto_response=RESPONSE_CONFIG['auto_response']
        )
        
        logger.info("All engines initialized successfully")
        
        # Main monitoring loop
        scan_count = 0
        while True:
            try:
                scan_count += 1
                
                # Process monitoring
                proc_anomaly = process_engine.detect_process_anomalies()
                if proc_anomaly:
                    logger.warning(f"Process anomaly detected: {proc_anomaly}")
                    correlation_engine.add_signal(
                        'process_monitor',
                        'anomaly',
                        proc_anomaly['average_risk'],
                        proc_anomaly
                    )
                
                # CLI monitoring
                cmd_anomaly = cli_engine.detect_command_anomalies()
                if cmd_anomaly:
                    logger.warning(f"Command anomaly detected: {cmd_anomaly}")
                    correlation_engine.add_signal(
                        'cli_monitor',
                        'anomaly',
                        cmd_anomaly.get('average_risk', cmd_anomaly.get('risk_score', 0)),
                        cmd_anomaly
                    )
                
                # File behavior monitoring
                mass_enc = file_engine.detect_mass_encryption()
                if mass_enc:
                    logger.critical(f"Mass encryption detected: {mass_enc}")
                    correlation_engine.add_signal(
                        'file_behavior',
                        'mass_encryption',
                        80.0,
                        mass_enc
                    )
                
                # Correlation analysis
                detection = correlation_engine.detect_ransomware()
                if detection:
                    logger.critical(f"RANSOMWARE DETECTED: {detection}")
                    
                    # Execute response
                    response = response_engine.respond_to_threat(detection)
                    logger.info(f"Response executed: {response}")
                    
                    # Send alerts (implement based on your needs)
                    send_alert(detection, response)
                
                # Periodic statistics
                if scan_count % 60 == 0:  # Every 60 scans
                    logger.info(f"Statistics: "
                              f"Scans={scan_count}, "
                              f"Threats={correlation_engine.detection_count}")
                
                # Cleanup
                process_engine.cleanup_dead_processes()
                
                # Sleep
                time.sleep(PERFORMANCE_CONFIG['scan_interval'])
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                time.sleep(5)
    
    except KeyboardInterrupt:
        logger.info("Service stopped by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
    finally:
        logger.info("Sentinel Guard service stopped")

def send_alert(detection, response):
    """Send alerts via configured channels"""
    # Implement email/webhook alerts based on ALERT_CONFIG
    pass

if __name__ == '__main__':
    main()
```

## Service Setup

### Windows Service Installation

Create `install_service.py`:

```python
# install_service.py
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import sys

class SentinelGuardService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SentinelGuard"
    _svc_display_name_ = "Sentinel Guard Ransomware Protection"
    _svc_description_ = "Real-time ransomware detection and response service"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
    
    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()
    
    def main(self):
        # Import and run service
        from service import main
        main()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SentinelGuardService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SentinelGuardService)
```

Install as Windows service:
```powershell
# Install service
python install_service.py install

# Start service
python install_service.py start

# Stop service
python install_service.py stop

# Remove service
python install_service.py remove
```

### Alternative: Task Scheduler

For simpler deployment:
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "python" -Argument "C:\Program Files\RansomShield\service.py"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "SentinelGuard" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
```

## Monitoring & Logging

### Log Locations
- **Main Log**: `C:\ProgramData\RansomShield\logs\sentinel.log`
- **Detection Log**: `C:\ProgramData\RansomShield\logs\detections.log`
- **Response Log**: `C:\ProgramData\RansomShield\logs\responses.log`

### Monitoring Metrics
- Detection rate
- False positive rate
- Response times
- System resource usage
- Alert delivery success

### Health Checks
Create `health_check.py`:
```python
import sys
from src.engines import *

try:
    # Test engine initialization
    FileBehaviorEngine()
    ProcessMonitorEngine()
    CLIMonitorEngine()
    CorrelationEngine()
    ResponseEngine()
    print("Health check: PASSED")
    sys.exit(0)
except Exception as e:
    print(f"Health check: FAILED - {e}")
    sys.exit(1)
```

Run periodically:
```powershell
python health_check.py
```

## Performance Tuning

### Optimize for Different Environments

**High-Performance Servers**:
```python
PROCESS_MONITOR_CONFIG = {
    'cpu_threshold': 85.0,  # Higher threshold
    'monitoring_interval': 3.0  # Less frequent
}
PERFORMANCE_CONFIG = {
    'scan_interval': 3.0
}
```

**Desktop Workstations**:
```python
PROCESS_MONITOR_CONFIG = {
    'cpu_threshold': 70.0,
    'monitoring_interval': 1.0
}
PERFORMANCE_CONFIG = {
    'scan_interval': 1.5
}
```

**File Servers**:
```python
FILE_BEHAVIOR_CONFIG = {
    'threshold_files_per_second': 25,  # Higher for file servers
    'time_window_seconds': 10  # Longer window
}
```

## Security Hardening

1. **Restrict File Permissions**
```powershell
icacls "C:\Program Files\RansomShield" /inheritance:r
icacls "C:\Program Files\RansomShield" /grant:r "Administrators:(OI)(CI)F"
icacls "C:\Program Files\RansomShield" /grant:r "SYSTEM:(OI)(CI)F"
```

2. **Enable Code Signing** (if applicable)
3. **Configure Windows Firewall** (if network features added)
4. **Regular Updates**: Schedule weekly checks for updates
5. **Audit Logging**: Enable detailed audit logs

## Troubleshooting

### Common Issues

**High CPU Usage**:
- Increase `scan_interval`
- Increase `monitoring_interval`
- Reduce `process_spawn_threshold`

**High Memory Usage**:
- Reduce `maxlen` in deques
- Clear caches more frequently
- Reduce `correlation_window`

**False Positives**:
- Increase thresholds
- Add processes to whitelist
- Tune entropy_threshold

**Missed Detections**:
- Decrease thresholds
- Reduce `min_signals`
- Decrease `scan_interval`

### Debug Mode
Enable debug logging:
```python
LOGGING_CONFIG = {
    'log_level': 'DEBUG'
}
```

## Maintenance

### Regular Tasks

**Daily**:
- Check logs for errors
- Review detection statistics
- Verify service is running

**Weekly**:
- Analyze false positives
- Review response actions
- Update threat signatures

**Monthly**:
- Performance review
- Update dependencies
- Backup configuration
- Test disaster recovery

### Update Procedure
```powershell
# Stop service
python install_service.py stop

# Backup current version
Copy-Item -Recurse "C:\Program Files\RansomShield" "C:\Backups\RansomShield-$(Get-Date -Format 'yyyyMMdd')"

# Update code
cd "C:\Program Files\RansomShield"
git pull

# Update dependencies
pip install -r requirements.txt --upgrade

# Run tests
python -m pytest test_v2_engines.py

# Start service
python install_service.py start
```

### Rollback Procedure
```powershell
# Stop service
python install_service.py stop

# Restore backup
Remove-Item -Recurse "C:\Program Files\RansomShield"
Copy-Item -Recurse "C:\Backups\RansomShield-YYYYMMDD" "C:\Program Files\RansomShield"

# Start service
python install_service.py start
```

## Production Checklist

Before going live:

- [ ] Configuration reviewed and tuned
- [ ] Logging configured and tested
- [ ] Alerts configured and tested
- [ ] Service installed and auto-starts
- [ ] Health checks in place
- [ ] Monitoring dashboard ready
- [ ] Team trained
- [ ] Documentation complete
- [ ] Rollback plan tested
- [ ] Performance baseline established

---

**Need Help?** Contact the RansomShield team or open an issue on GitHub.
