# Quick Start Guide - Sentinel Guard

Get up and running with RansomShield Sentinel Guard in 5 minutes!

## Installation

### Step 1: System Requirements
- Windows 10 (build 1809+) or Windows 11
- Python 3.8 or higher
- 4GB RAM minimum
- Administrator privileges

### Step 2: Install Python
Download and install Python from [python.org](https://www.python.org/downloads/)

Verify installation:
```bash
python --version
```

### Step 3: Clone Repository
```bash
git clone https://github.com/Nady-Emad/RansomShield.git
cd RansomShield
```

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

## First Run

### Example 1: Analyze a File
Create a test script `analyze_file.py`:

```python
from src.engines import FileBehaviorEngine

# Initialize engine
engine = FileBehaviorEngine()

# Analyze a file
result = engine.analyze_file("C:\\Users\\YourName\\Documents\\example.pdf")

# Display results
print(f"File: {result['path']}")
print(f"Suspicious: {result['suspicious']}")
print(f"Entropy: {result['entropy']:.2f}")
print(f"Risk Score: {result['risk_score']:.1f}%")
if result['reasons']:
    print(f"Reasons: {', '.join(result['reasons'])}")
```

Run it:
```bash
python analyze_file.py
```

### Example 2: Monitor Processes
Create `monitor_processes.py`:

```python
from src.engines import ProcessMonitorEngine

# Initialize engine
engine = ProcessMonitorEngine()

# Scan all processes
suspicious = engine.scan_all_processes()

# Display results
print(f"Found {len(suspicious)} suspicious processes")
for proc in suspicious[:5]:  # Show top 5
    info = proc['info']
    print(f"PID: {info['pid']}")
    print(f"Name: {info['name']}")
    print(f"CPU: {info['cpu_percent']:.1f}%")
    print(f"Risk Score: {proc['risk_score']:.1f}")
    print("---")
```

Run it:
```bash
python monitor_processes.py
```

### Example 3: Check Commands
Create `check_command.py`:

```python
from src.engines import CLIMonitorEngine

# Initialize engine
engine = CLIMonitorEngine()

# Test commands
commands = [
    "dir C:\\Users",
    "vssadmin delete shadows /all",
    "bcdedit /set recoveryenabled No"
]

for cmd in commands:
    result = engine.analyze_command(cmd)
    print(f"Command: {cmd}")
    print(f"Suspicious: {result['suspicious']}")
    print(f"Risk Score: {result['risk_score']:.1f}")
    print("---")
```

Run it:
```bash
python check_command.py
```

### Example 4: Complete Detection System
Create `full_monitor.py`:

```python
import time
from src.engines import (
    FileBehaviorEngine,
    ProcessMonitorEngine,
    CLIMonitorEngine,
    CorrelationEngine,
    ResponseEngine
)

# Initialize all engines
print("Initializing Sentinel Guard...")
file_engine = FileBehaviorEngine()
process_engine = ProcessMonitorEngine()
cli_engine = CLIMonitorEngine()
correlation_engine = CorrelationEngine()
response_engine = ResponseEngine(auto_response=False)  # Manual mode

print("Starting monitoring...")
for i in range(10):  # Monitor for 10 cycles
    print(f"\n=== Scan #{i+1} ===")
    
    # Scan processes
    proc_anomaly = process_engine.detect_process_anomalies()
    if proc_anomaly:
        print(f"⚠ Process anomaly detected!")
        correlation_engine.add_signal(
            'process_monitor',
            'anomaly',
            proc_anomaly['average_risk']
        )
    
    # Check for ransomware
    detection = correlation_engine.detect_ransomware()
    if detection:
        print(f"🚨 RANSOMWARE DETECTED!")
        print(f"Composite Score: {detection['composite_score']:.1f}")
        print(f"Confidence: {detection['confidence']:.1f}%")
        print(f"Severity: {detection['severity']}")
        
        # Show what would happen with auto-response
        level = response_engine.determine_response_level(
            detection['composite_score'],
            detection['severity']
        )
        print(f"Recommended Action: {level.name}")
    else:
        # Show current threat level
        score, _ = correlation_engine.calculate_composite_score()
        print(f"Threat Level: {score:.1f}%")
    
    time.sleep(3)  # Wait 3 seconds

print("\nMonitoring complete!")

# Show statistics
print("\n=== Statistics ===")
print(f"Process scans: {process_engine.total_processes_scanned}")
print(f"Suspicious processes: {process_engine.suspicious_processes_found}")
print(f"Total signals: {correlation_engine.total_signals}")
print(f"Detections: {correlation_engine.detection_count}")
```

Run it:
```bash
python full_monitor.py
```

### Example 5: PyQt5 GUI Integration
Create `gui_monitor.py`:

```python
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget
from PyQt5.QtCore import Qt
from workers import AdvancedMonitorWorker

class MonitorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel Guard Monitor")
        self.setGeometry(100, 100, 800, 600)
        
        # Create text display
        self.text_display = QTextEdit()
        self.text_display.setReadOnly(True)
        
        layout = QVBoxLayout()
        layout.addWidget(self.text_display)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
        # Create worker
        self.worker = AdvancedMonitorWorker(scan_interval=2.0, auto_response=False)
        self.worker.detection_signal.connect(self.on_detection)
        self.worker.alert_signal.connect(self.on_alert)
        self.worker.status_signal.connect(self.on_status)
        self.worker.statistics_signal.connect(self.on_statistics)
        
        # Start monitoring
        self.worker.start()
        self.log("Sentinel Guard started")
    
    def log(self, message):
        self.text_display.append(message)
    
    def on_detection(self, detection):
        self.log(f"🚨 DETECTION: {detection['message']}")
        self.log(f"   Score: {detection['composite_score']:.1f}%")
        self.log(f"   Confidence: {detection['confidence']:.1f}%")
    
    def on_alert(self, alert):
        self.log(f"⚠ ALERT: {alert.get('message', alert['type'])}")
    
    def on_status(self, status):
        self.log(f"ℹ {status['message']}")
    
    def on_statistics(self, stats):
        self.log(f"📊 Stats: {stats['scan_count']} scans, "
                f"{stats['detection_count']} detections, "
                f"Threat: {stats['correlation']['current_composite_score']:.1f}%")
    
    def closeEvent(self, event):
        self.worker.stop()
        self.worker.wait()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MonitorWindow()
    window.show()
    sys.exit(app.exec_())
```

Run it:
```bash
python gui_monitor.py
```

## Running Tests

Verify everything works:
```bash
# Run all tests
pytest test_v2_engines.py -v

# Run specific tests
pytest test_v2_engines.py::TestFileBehaviorEngine -v
pytest test_v2_engines.py::TestPerformanceMetrics -v
pytest test_v2_engines.py::TestAccuracyMetrics -v
```

## Common Issues

### Permission Errors
Some operations require administrator privileges. Run your terminal as Administrator.

### Import Errors
Make sure you're in the RansomShield directory:
```bash
cd /path/to/RansomShield
```

### PyQt5 Installation Issues
If PyQt5 fails to install:
```bash
pip install PyQt5 --user
```

Or use wheels:
```bash
pip install PyQt5 --no-cache-dir
```

## Next Steps

1. Read the [Deployment Guide](deployment_guide.md) for production setup
2. Review the full [README](../README.md) for detailed documentation
3. Customize engine parameters for your environment
4. Set up logging and alerting
5. Configure response policies

## Tips

- Start with `auto_response=False` to monitor without taking action
- Adjust thresholds based on your environment
- Monitor false positives and tune accordingly
- Test in a safe environment first
- Keep detailed logs of all detections

## Support

- Check the main [README](../README.md)
- Review [Deployment Guide](deployment_guide.md)
- Open an issue on GitHub

Happy hunting! 🛡️
