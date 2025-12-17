"""
Ransomware Defense Kit v1.0 - Professional GUI
Improved UI/UX with proper styling and layout
"""

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
    QTableWidget, QTableWidgetItem, QTextEdit, QFormLayout, QLineEdit, 
    QSpinBox, QCheckBox, QMessageBox, QFileDialog, QGroupBox, QToolBar, 
    QPushButton, QTabWidget, QProgressBar, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QColor, QIcon, QPixmap

import json
import os
import sys
from datetime import datetime

# Performance monitoring UI and worker
from ui.performance_dashboard_enhanced import create_performance_tab
from workers.performance_worker import PerformanceWorker

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.loader import ConfigLoader
from config.validator import ConfigValidator
from workers.monitor_worker import MonitorWorker
from workers.advanced_monitor_worker import AdvancedMonitorWorker
from core.risk_engine import RiskEngine
from core.mitigator import ProcessMitigator
from gui.dialogs import CriticalAlertDialog, SuccessDialog
from utils.privilege_check import is_admin
from core.emergency_handler import EmergencyHandler
from core.tamper_detector import TamperDetector
from utils.logger import EventLogger
from utils.privilege_check import is_admin
from gui.styles import STYLESHEET, COLOR_PRIMARY, COLOR_SUCCESS, COLOR_CRITICAL, COLOR_WARNING, COLOR_TEXT_DARK
from gui.dialogs import CriticalAlertDialog, SuccessDialog, WarningDialog
from gui.widgets import Toast
from gui.scanner_tab import ScannerPage


class MainWindow(QMainWindow):
    """Main application window with professional UI."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ Ransomware Defense Kit v2.0 (Advanced)")
        self.setGeometry(50, 50, 1400, 900)
        self.setStyleSheet(STYLESHEET)  # Use new professional stylesheet
        
        # SECURITY: Check admin privileges (can be disabled for development)
        # Set environment variable SKIP_ADMIN_CHECK=1 to disable this check during development
        if os.environ.get('SKIP_ADMIN_CHECK') != '1' and not is_admin():
            msg_box = QMessageBox(None)
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("⚠️ Administrator Privileges Required")
            msg_box.setText(
                "Ransomware Defense Kit requires administrator/root privileges to:\n\n"
                "• Monitor system-level processes\n"
                "• Terminate malicious processes\n"
                "• Create file system canaries\n"
                "• Access low-level system APIs\n\n"
                "Please restart this application as Administrator (Windows) or with sudo (Linux/Mac)."
            )
            
            # Add three buttons
            btn_exit = msg_box.addButton("Exit (Recommended)", QMessageBox.RejectRole)
            btn_monitor = msg_box.addButton("Monitor-Only Mode", QMessageBox.AcceptRole)
            btn_force = msg_box.addButton("Run Anyway (Full Features)", QMessageBox.YesRole)
            msg_box.setDefaultButton(btn_exit)
            
            msg_box.exec_()
            clicked = msg_box.clickedButton()
            
            if clicked == btn_exit:
                sys.exit(1)
            elif clicked == btn_monitor:
                # Limited mode - disable mitigation features
                QMessageBox.information(
                    None,
                    "Monitor-Only Mode",
                    "Running in MONITOR-ONLY mode.\n\n"
                    "Process termination and mitigation features are DISABLED.\n"
                    "Only monitoring and logging will be active."
                )
            elif clicked == btn_force:
                # Force run with warning
                QMessageBox.warning(
                    None,
                    "⚠️ Running Without Admin",
                    "WARNING: Running with full features without admin privileges.\n\n"
                    "Some features may fail silently or cause errors:\n"
                    "• Process termination may not work\n"
                    "• System-level monitoring may be incomplete\n"
                    "• Canary files may not be created\n\n"
                    "Use at your own risk!"
                )
        
        # Load config
        self.config_loader = ConfigLoader('config.json')
        self.config = self.config_loader.load()
        
        # Load whitelist and blacklist
        self.whitelist_path = 'whitelist.json'
        self.blacklist_path = 'blacklist.json'
        self.whitelist = self._load_list(self.whitelist_path)
        self.blacklist = self._load_list(self.blacklist_path)
        # Sanitize monitoring directories to avoid startup blocking on missing paths
        try:
            mon = self.config.setdefault('monitoring', {})
            dirs = mon.get('directories', []) or []
            userprofile = os.environ.get('USERPROFILE')
            suggested = []
            if userprofile:
                suggested = [
                    os.path.join(userprofile, 'Documents'),
                    os.path.join(userprofile, 'Desktop'),
                ]
            valid_dirs = [d for d in dirs if isinstance(d, str) and os.path.exists(d)]
            for s in suggested:
                if os.path.exists(s) and s not in valid_dirs:
                    valid_dirs.append(s)
            # Fallback to current working directory if none valid
            if not valid_dirs:
                try:
                    cwd = os.getcwd()
                    if os.path.exists(cwd):
                        valid_dirs = [cwd]
                except Exception:
                    pass
            mon['directories'] = valid_dirs
        except Exception:
            pass
        try:
            errors = ConfigValidator.validate(self.config)
            if errors:
                # Filter to only string errors and exclude empty/non-meaningful ones
                clean_errors = [
                    str(e).strip() 
                    for e in errors 
                    if isinstance(e, str) and str(e).strip() and str(e).strip() not in ['[]', 'True', 'False', 'None']
                ]
                if clean_errors:
                    # Show warning but allow app to continue with sanitized defaults
                    msg = "\n".join([f"- {e}" for e in clean_errors])
                    QMessageBox.warning(self, "Configuration Warning", f"Some configuration issues were detected and fixed:\n\n{msg}\n\nMonitoring will use available directories.")
        except Exception:
            # Fallback: ensure minimal defaults so UI can still open
            if not isinstance(self.config, dict):
                self.config = {}
        
        # Logger
        self.logger = EventLogger(
            jsonl_path=self.config['logging']['jsonl_file'],
            csv_path=self.config['logging']['csv_file']
        )
        
        # Risk engine
        self.risk_engine = RiskEngine(self.config['risk_scoring'])

        # Mitigator & emergency/tamper handlers
        self.mitigator = ProcessMitigator(self.config)
        self.emergency_handler = EmergencyHandler(self.config, self.mitigator, self.logger)
        self.tamper_detector = TamperDetector(self.config, self.logger)
        self.tamper_detector.initialize()
        
        # Monitor workers (v2.0 with advanced multi-engine system)
        self.monitor_worker = None  # Legacy v1.0
        self.advanced_monitor_worker = None  # v2.0 with 5 engines
        self.monitor_thread = None
        self.use_advanced_mode = False  # Default to enhanced legacy (entropy/ML/family/playbooks)

        # Performance monitoring worker (v2.0)
        self.perf_worker = None
        self.perf_thread = None
        self.perf_labels = {}
        
        # State
        self.is_monitoring = False
        self.current_mode = self.config['mitigation']['mode']
        self.live_events = []
        self.flagged_processes = []
        
        # Setup UI
        self._create_ui()
        
        # Status updates
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status_bar)
        self.status_timer.start(1000)
        
        # Risk decay timer
        self.decay_timer = QTimer()
        self.decay_timer.timeout.connect(self._decay_risk)
        self.decay_timer.start(5000)

        # Tamper detection timer
        self.tamper_timer = QTimer()
        self.tamper_timer.timeout.connect(self._check_defense_integrity)
        self.tamper_timer.start(60000)
        
        self.logger.log_event({
            'timestamp': datetime.now().isoformat(),
            'severity': 'INFO',
            'rule': 'APP_STARTUP',
            'message': 'Ransomware Defense Kit started',
            'mode': self.current_mode
        })
    
    def _create_ui(self):
        """Build main UI."""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        toolbar = self._create_toolbar()
        self.addToolBar(toolbar)
        
        self.tabs = QTabWidget()
        # Improve tab icon sizing and spacing
        self.tabs.setIconSize(QSize(22, 22))
        self.tabs.tabBar().setMinimumHeight(52)
        main_layout.addWidget(self.tabs)
        
        self.tab_dashboard = self._create_dashboard_tab()
        self.tab_events = self._create_events_tab()
        self.tab_logs = self._create_logs_tab()
        self.tab_settings = self._create_settings_tab()
        self.tab_about = self._create_about_tab()

        # Performance tab
        self.tab_performance = create_performance_tab(self)
        
           # Scanner tab
        self.tab_scanner = ScannerPage(self.config, self.logger, self)
        
        # Add tabs with proper sizing
        self.tabs.addTab(self.tab_dashboard, "📊 Dashboard")
        self.tabs.addTab(self.tab_events, "📋 Live Events")
        self.tabs.addTab(self.tab_logs, "📜 All Logs")
        self.tabs.addTab(self.tab_scanner, "🔍 Scanner")
        self.tabs.addTab(self.tab_performance, "📈 Performance")
        self.tabs.addTab(self.tab_settings, "⚙️ Settings")
        self.tabs.addTab(self.tab_about, "ℹ️ About")
        
        # Set tab bar height to accommodate text + icon
        self.tabs.tabBar().setMinimumHeight(50)
        
        self.tabs.setCurrentIndex(0)
        
        self.status_label = QLabel("Ready | Press ▶ Start Monitoring")
        self.status_label.setStyleSheet("color: #666; padding: 8px;")
        self.statusBar().addWidget(self.status_label)
    
    def _create_toolbar(self):
        """Create professional toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        
        self.btn_start_stop = QPushButton("▶ START MONITORING")
        self.btn_start_stop.setMinimumWidth(150)
        self.btn_start_stop.setMinimumHeight(40)
        self.btn_start_stop.setFont(QFont("Arial", 11, QFont.Bold))
        self.btn_start_stop.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_SUCCESS};
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
            }}
            QPushButton:hover {{ background-color: #229954; }}
            QPushButton:pressed {{ background-color: #1E8449; }}
        """)
        self.btn_start_stop.clicked.connect(self._toggle_monitoring)
        toolbar.addWidget(self.btn_start_stop)

        toolbar.addSeparator()
        self.btn_lockdown = QPushButton("🔴 EMERGENCY LOCKDOWN")
        self.btn_lockdown.setMinimumWidth(180)
        self.btn_lockdown.setMinimumHeight(40)
        self.btn_lockdown.setFont(QFont("Arial", 11, QFont.Bold))
        self.btn_lockdown.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CRITICAL};
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
            }}
            QPushButton:hover {{ background-color: #A93226; }}
            QPushButton:pressed {{ background-color: #922B21; }}
        """)
        self.btn_lockdown.clicked.connect(self._on_emergency_lockdown)
        toolbar.addWidget(self.btn_lockdown)
        
        toolbar.addSeparator()
        toolbar.addWidget(QLabel("Mode:"))
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["Monitor-Only", "Auto-Mitigate"])
        self.combo_mode.setMinimumWidth(120)
        self.combo_mode.currentTextChanged.connect(self._on_mode_changed)
        toolbar.addWidget(self.combo_mode)
        
        toolbar.addSeparator()
        self.btn_export = QPushButton("📊 EXPORT LOGS")
        self.btn_export.setMinimumWidth(120)
        self.btn_export.clicked.connect(self._export_logs)
        toolbar.addWidget(self.btn_export)
        
        # 🆕 ADD DEMO BUTTON
        self.btn_demo = QPushButton("🧪 TEST DEMO")
        self.btn_demo.setMinimumWidth(100)
        self.btn_demo.setStyleSheet(f"""
            QPushButton {{
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11px;
            }}
            QPushButton:hover {{ background-color: #8e44ad; }}
        """)
        self.btn_demo.clicked.connect(self._test_demo_event)
        toolbar.addWidget(self.btn_demo)

        # Add spacer to push items to the left
        spacer = QWidget()
        spacer.setSizePolicy(spacer.sizePolicy().Expanding, spacer.sizePolicy().Preferred)
        toolbar.addWidget(spacer)
        
        return toolbar
    
    def _create_dashboard_tab(self):
        """Professional dashboard tab with full-page scrollable view."""
        # Main container widget
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create scrollable area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background-color: #f5f5f5; }")
        
        # Content widget that will be scrolled
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Set content background color
        content_widget.setStyleSheet("background-color: #f5f5f5;")
        
        # System Status Section
        status_group = QGroupBox("🔍 SYSTEM STATUS")
        status_group.setStyleSheet("""
            QGroupBox {
                background-color: #ffffff;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 15px;
                font-weight: 600;
                font-size: 13px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
            }
        """)
        status_form = QFormLayout(status_group)
        status_form.setSpacing(12)
        status_form.setContentsMargins(15, 15, 15, 15)
        
        self.lbl_status = QLabel("STOPPED")
        self.lbl_status.setFont(QFont("Arial", 16, QFont.Bold))
        self.lbl_status.setStyleSheet("color: #e74c3c; padding: 8px; background: #ffe6e6; border-radius: 6px;")
        status_form.addRow("Status:", self.lbl_status)
        
        self.lbl_mode_display = QLabel("Monitor-Only")
        self.lbl_mode_display.setFont(QFont("Arial", 13))
        self.lbl_mode_display.setStyleSheet("color: #32b8c6; padding: 6px;")
        status_form.addRow("Mode:", self.lbl_mode_display)
        
        layout.addWidget(status_group)
        
        # ⭐ IMPROVED RISK SCORE SECTION
        risk_group = QGroupBox("⚠️ RISK ASSESSMENT")
        risk_group.setStyleSheet("""
            QGroupBox {
                background-color: #ffffff;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 15px;
                font-weight: 600;
                font-size: 13px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
            }
        """)
        risk_form = QFormLayout(risk_group)
        risk_form.setSpacing(15)
        risk_form.setContentsMargins(15, 15, 15, 15)
        
        # Risk Score Label
        risk_label = QLabel("Risk Score:")
        risk_label.setFont(QFont("Arial", 12, QFont.Bold))
        risk_label.setStyleSheet("color: #333;")
        
        # Risk Progress Bar (MAIN FIX)
        self.risk_progress = QProgressBar()
        self.risk_progress.setMaximum(200)
        self.risk_progress.setValue(0)
        self.risk_progress.setMinimumHeight(35)
        self.risk_progress.setTextVisible(False)
        self.risk_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #ddd;
                border-radius: 8px;
                background-color: #f5f5f5;
                height: 35px;
            }
            QProgressBar::chunk {
                background-color: #27ae60;
                border-radius: 6px;
            }
        """)
        risk_form.addRow(risk_label, self.risk_progress)
        
        # Risk Text Label (Shows "0 / 200")
        self.lbl_risk_text = QLabel("0 / 200")
        self.lbl_risk_text.setFont(QFont("Arial", 14, QFont.Bold))
        self.lbl_risk_text.setStyleSheet("color: #27ae60; padding: 10px; background: #f0f9f8; border-radius: 6px; text-align: center;")
        self.lbl_risk_text.setAlignment(Qt.AlignCenter)
        risk_form.addRow("Current Level:", self.lbl_risk_text)
        
        # Risk Status Text
        self.lbl_risk_status = QLabel("🟢 Safe - No threats detected")
        self.lbl_risk_status.setFont(QFont("Arial", 11))
        self.lbl_risk_status.setStyleSheet("color: #27ae60; padding: 8px; font-weight: 500;")
        risk_form.addRow("Status:", self.lbl_risk_status)
        
        layout.addWidget(risk_group)
        
        # Monitored Directories Section
        dirs_group = QGroupBox("📁 MONITORED DIRECTORIES")
        dirs_group.setStyleSheet("""
            QGroupBox {
                background-color: #ffffff;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 15px;
                font-weight: 600;
                font-size: 13px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
            }
        """)
        dirs_form = QFormLayout(dirs_group)
        dirs_form.setContentsMargins(15, 15, 15, 15)
        self.lbl_dirs = QLabel()
        self.lbl_dirs.setStyleSheet("color: #555; padding: 10px; background: #f9f9f9; border-radius: 6px; line-height: 1.6;")
        self._update_dirs_label()
        dirs_form.addRow("Paths:", self.lbl_dirs)
        layout.addWidget(dirs_group)
        
        # Event Summary Section
        summary_group = QGroupBox("📊 EVENT SUMMARY")
        summary_group.setStyleSheet("""
            QGroupBox {
                background-color: #ffffff;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 15px;
                font-weight: 600;
                font-size: 13px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
            }
        """)
        summary_form = QFormLayout(summary_group)
        summary_form.setSpacing(12)
        summary_form.setContentsMargins(15, 15, 15, 15)
        
        self.lbl_total_events = QLabel("0")
        self.lbl_total_events.setFont(QFont("Arial", 13, QFont.Bold))
        self.lbl_total_events.setStyleSheet("color: #32b8c6; padding: 6px; background: #f0f8fa; border-radius: 4px;")
        summary_form.addRow("Total Events:", self.lbl_total_events)
        
        self.lbl_critical_events = QLabel("0")
        self.lbl_critical_events.setFont(QFont("Arial", 13, QFont.Bold))
        self.lbl_critical_events.setStyleSheet("color: #e74c3c; padding: 6px; background: #ffe6e6; border-radius: 4px;")
        summary_form.addRow("🔴 Critical:", self.lbl_critical_events)
        
        self.lbl_warning_events = QLabel("0")
        self.lbl_warning_events.setFont(QFont("Arial", 13, QFont.Bold))
        self.lbl_warning_events.setStyleSheet("color: #f39c12; padding: 6px; background: #fff3e0; border-radius: 4px;")
        summary_form.addRow("🟡 Warnings:", self.lbl_warning_events)
        
        self.lbl_info_events = QLabel("0")
        self.lbl_info_events.setFont(QFont("Arial", 13, QFont.Bold))
        self.lbl_info_events.setStyleSheet("color: #32b8c6; padding: 6px; background: #f0f8fa; border-radius: 4px;")
        summary_form.addRow("🔵 Info:", self.lbl_info_events)
        
        layout.addWidget(summary_group)
        
        # Flagged Processes Section
        processes_group = QGroupBox("⚡ FLAGGED PROCESSES")
        processes_group.setStyleSheet("""
            QGroupBox {
                background-color: #ffffff;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 15px;
                font-weight: 600;
                font-size: 13px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
            }
        """)
        processes_form = QFormLayout(processes_group)
        processes_form.setContentsMargins(15, 15, 15, 15)
        self.lbl_flagged = QLabel("None")
        self.lbl_flagged.setFont(QFont("Arial", 12))
        self.lbl_flagged.setStyleSheet("color: #555; padding: 12px; background: #f9f9f9; border-radius: 6px; min-height: 30px;")
        self.lbl_flagged.setWordWrap(True)
        processes_form.addRow("Detected:", self.lbl_flagged)
        layout.addWidget(processes_group)
        
        layout.addStretch()
        
        # Add content widget to scroll area
        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll)
        
        return main_widget
    
    def _create_events_tab(self):
        """Live events table with click handler and detail panel."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Header
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f9f9f9;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
        """)
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(15, 15, 15, 15)
        
        title = QLabel("📋 REAL-TIME EVENT MONITORING")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #333;")
        header_layout.addWidget(title)
        
        subtitle = QLabel("Click on any row to see full event details")
        subtitle.setFont(QFont("Arial", 11))
        subtitle.setStyleSheet("color: #888;")
        header_layout.addWidget(subtitle)
        
        layout.addWidget(header_frame)
        
        # Main container with table and detail panel
        container = QWidget()
        container_layout = QHBoxLayout(container)
        container_layout.setSpacing(15)
        container_layout.setContentsMargins(0, 0, 0, 0)
        
        # LEFT SIDE: Events Table
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        self.table_events = QTableWidget()
        self.table_events.setColumnCount(7)
        self.table_events.setHorizontalHeaderLabels([
            "Timestamp", "Severity", "Rule", "File Path", "PID", "Process", "Action"
        ])
        
        # Set column widths for consistent display
        self.table_events.setColumnWidth(0, 150)
        self.table_events.setColumnWidth(1, 100)
        self.table_events.setColumnWidth(2, 140)
        self.table_events.setColumnWidth(3, 280)
        self.table_events.setColumnWidth(4, 70)
        self.table_events.setColumnWidth(5, 120)
        self.table_events.setColumnWidth(6, 100)
        
        # Table behavior
        self.table_events.setAlternatingRowColors(True)
        self.table_events.setSelectionBehavior(self.table_events.SelectRows)
        self.table_events.setSelectionMode(self.table_events.SingleSelection)
        self.table_events.setMinimumHeight(300)
        
        # Table styling - CONSISTENT
        self.table_events.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                gridline-color: #f0f0f0;
            }
            QTableWidget::item {
                padding: 10px;
                border: none;
                height: 35px;
            }
            QTableWidget::item:alternated-background {
                background-color: #f9f9f9;
            }
            QHeaderView::section {
                background-color: #32b8c6;
                color: white;
                padding: 12px;
                border: none;
                font-weight: bold;
                font-size: 12px;
                height: 40px;
            }
            QTableWidget::item:selected {
                background-color: #d4f1f7;
                color: black;
            }
            QTableWidget::item:hover {
                background-color: #f0f8fa;
            }
        """)
        
        # Connect row click signal
        self.table_events.itemSelectionChanged.connect(self._on_event_row_selected)
        
        left_layout.addWidget(self.table_events)
        container_layout.addWidget(left_panel, 3)
        
        # RIGHT SIDE: Detail Panel
        detail_panel = QFrame()
        detail_panel.setFixedWidth(420)
        detail_panel.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
            }
        """)
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(15, 15, 15, 15)
        detail_layout.setSpacing(10)
        
        detail_title = QLabel("📊 Event Details")
        detail_title.setFont(QFont("Arial", 13, QFont.Bold))
        detail_title.setStyleSheet("color: #333;")
        detail_layout.addWidget(detail_title)
        
        detail_layout.addWidget(QFrame())  # Separator
        
        # Scrollable detail area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setMinimumWidth(380)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)
        
        self.detail_widget = QWidget()
        self.detail_widget.setMinimumWidth(360)
        self.detail_form = QFormLayout(self.detail_widget)
        self.detail_form.setSpacing(15)
        self.detail_form.setContentsMargins(10, 10, 10, 10)
        self.detail_form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        # Create labels for each field
        self.detail_labels = {
            'timestamp': ('📅 Timestamp:', QLabel('None')),
            'severity': ('🔴 Severity:', QLabel('None')),
            'rule': ('📋 Rule:', QLabel('None')),
            'path': ('📁 File Path:', QLabel('None')),
            'pid': ('⚙️ Process ID:', QLabel('None')),
            'process_name': ('🔧 Process Name:', QLabel('None')),
            'action': ('✅ Action:', QLabel('None')),
            'message': ('💬 Message:', QLabel('None')),
        }
        
        # Style detail labels
        for label_text, label_widget in self.detail_labels.values():
            label_widget.setFont(QFont("Arial", 11))
            label_widget.setWordWrap(True)
            label_widget.setMinimumHeight(40)
            label_widget.setMinimumWidth(160)
            label_widget.setStyleSheet("color: #555; padding: 12px; background: #f9f9f9; border-radius: 4px; border: 1px solid #e0e0e0;")
            title_label = QLabel(label_text)
            title_label.setFont(QFont("Arial", 11, QFont.Bold))
            title_label.setStyleSheet("color: #333; min-width: 150px; padding: 12px;")
            self.detail_form.addRow(title_label, label_widget)
        
        scroll.setWidget(self.detail_widget)
        detail_layout.addWidget(scroll)
        
        container_layout.addWidget(detail_panel, 1)
        
        layout.addWidget(container)
        
        # Footer with stats
        footer_frame = QFrame()
        footer_frame.setStyleSheet("""
            QFrame {
                background-color: #f9f9f9;
                border-radius: 6px;
                border: 1px solid #e0e0e0;
            }
        """)
        footer_layout = QHBoxLayout(footer_frame)
        footer_layout.setContentsMargins(15, 10, 15, 10)
        
        self.lbl_event_count = QLabel("Total Events: 0")
        self.lbl_event_count.setFont(QFont("Arial", 11, QFont.Bold))
        self.lbl_event_count.setStyleSheet("color: #32b8c6;")
        footer_layout.addWidget(self.lbl_event_count)
        
        footer_layout.addStretch()
        
        self.lbl_last_event = QLabel("No events yet")
        self.lbl_last_event.setFont(QFont("Arial", 11))
        self.lbl_last_event.setStyleSheet("color: #888;")
        footer_layout.addWidget(self.lbl_last_event)
        
        layout.addWidget(footer_frame)
        
        return widget

    def _create_logs_tab(self):
        """Display all logs from files with side-by-side layout."""
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        # Header
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f9f9f9;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
        """)
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(15, 15, 15, 15)
        
        title = QLabel("📜 COMPLETE LOG HISTORY")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #333;")
        header_layout.addWidget(title)
        
        subtitle = QLabel("All historical logs from JSONL and CSV files")
        subtitle.setFont(QFont("Arial", 11))
        subtitle.setStyleSheet("color: #888;")
        header_layout.addWidget(subtitle)
        
        main_layout.addWidget(header_frame)
        
        # Control buttons
        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        control_layout.setContentsMargins(0, 0, 0, 0)
        
        self.btn_refresh_logs = QPushButton("🔄 REFRESH LOGS")
        self.btn_refresh_logs.setMinimumWidth(120)
        self.btn_refresh_logs.setStyleSheet("""
            QPushButton {
                background-color: #32b8c6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #2da6b3; }
        """)
        self.btn_refresh_logs.clicked.connect(self._load_all_logs)
        control_layout.addWidget(self.btn_refresh_logs)
        
        control_layout.addWidget(QLabel("Filter by Severity:"))
        self.combo_severity_filter = QComboBox()
        self.combo_severity_filter.addItems(["All", "CRITICAL", "WARNING", "INFO"])
        self.combo_severity_filter.setMinimumWidth(120)
        self.combo_severity_filter.currentTextChanged.connect(self._filter_logs_table)
        control_layout.addWidget(self.combo_severity_filter)
        
        control_layout.addWidget(QLabel("Search:"))
        self.search_logs = QLineEdit()
        self.search_logs.setPlaceholderText("Search by rule, path, or process...")
        self.search_logs.setMinimumWidth(250)
        self.search_logs.textChanged.connect(self._filter_logs_table)
        control_layout.addWidget(self.search_logs)
        
        control_layout.addStretch()
        
        self.btn_clear_logs = QPushButton("🗑️ CLEAR OLD LOGS")
        self.btn_clear_logs.setMinimumWidth(120)
        self.btn_clear_logs.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #c0392b; }
        """)
        self.btn_clear_logs.clicked.connect(self._clear_logs)
        control_layout.addWidget(self.btn_clear_logs)
        
        main_layout.addWidget(control_frame)
        
        # Create horizontal container for table and details
        content_frame = QFrame()
        content_layout = QHBoxLayout(content_frame)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(15)
        
        # Logs table (LEFT SIDE - 70% width)
        self.table_logs = QTableWidget()
        self.table_logs.setColumnCount(8)
        self.table_logs.setHorizontalHeaderLabels([
            "Timestamp", "Severity", "Rule", "File Path", "PID", "Process", "Action", "Message"
        ])
        self.table_logs.setColumnWidth(0, 160)
        self.table_logs.setColumnWidth(1, 100)
        self.table_logs.setColumnWidth(2, 140)
        self.table_logs.setColumnWidth(3, 250)
        self.table_logs.setColumnWidth(4, 70)
        self.table_logs.setColumnWidth(5, 120)
        self.table_logs.setColumnWidth(6, 100)
        self.table_logs.setColumnWidth(7, 200)
        self.table_logs.setAlternatingRowColors(True)
        self.table_logs.setSelectionBehavior(self.table_logs.SelectRows)
        self.table_logs.setSelectionMode(self.table_logs.SingleSelection)
        self.table_logs.setMinimumHeight(500)
        self.table_logs.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                gridline-color: #f0f0f0;
            }
            QTableWidget::item {
                padding: 10px;
                border: none;
                height: 35px;
            }
            QTableWidget::item:alternated-background {
                background-color: #f9f9f9;
            }
            QHeaderView::section {
                background-color: #32b8c6;
                color: white;
                padding: 12px;
                border: none;
                font-weight: bold;
                font-size: 12px;
                height: 40px;
            }
            QTableWidget::item:selected {
                background-color: #d4f1f7;
                color: black;
            }
            QTableWidget::item:hover {
                background-color: #f0f8fa;
            }
        """)
        self.table_logs.itemSelectionChanged.connect(self._on_log_row_selected)
        
        # Add table to LEFT side (70% width)
        content_layout.addWidget(self.table_logs, 7)
        
        # Detail panel for selected log (RIGHT SIDE - 30% width)
        detail_frame = QFrame()
        detail_frame.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
            }
        """)
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.setContentsMargins(15, 15, 15, 15)
        detail_layout.setSpacing(12)
        
        detail_title = QLabel("📋 Log Details")
        detail_title.setFont(QFont("Arial", 13, QFont.Bold))
        detail_title.setStyleSheet("color: #333;")
        detail_layout.addWidget(detail_title)
        
        # Scrollable form for details
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")
        
        self.log_detail_widget = QWidget()
        self.log_detail_form = QFormLayout(self.log_detail_widget)
        self.log_detail_form.setSpacing(15)
        self.log_detail_form.setContentsMargins(10, 10, 10, 10)
        self.log_detail_form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        # Create detail labels dictionary
        self.log_detail_labels = {
            'timestamp': ('📅 Timestamp:', QLabel('N/A')),
            'severity': ('🔴 Severity:', QLabel('N/A')),
            'rule': ('📋 Rule:', QLabel('N/A')),
            'path': ('📁 File Path:', QLabel('N/A')),
            'pid': ('⚙️ Process ID:', QLabel('N/A')),
            'process_name': ('🔧 Process Name:', QLabel('N/A')),
            'action': ('✅ Action:', QLabel('N/A')),
            'message': ('💬 Message:', QLabel('N/A')),
        }
        
        # Add labels to form
        for label_text, label_widget in self.log_detail_labels.values():
            label_widget.setFont(QFont("Arial", 11))
            label_widget.setWordWrap(True)
            label_widget.setMinimumHeight(40)
            label_widget.setStyleSheet("color: #555; padding: 12px; background: #f9f9f9; border-radius: 4px; border: 1px solid #e0e0e0;")
            title_label = QLabel(label_text)
            title_label.setFont(QFont("Arial", 11, QFont.Bold))
            title_label.setStyleSheet("color: #333; min-width: 150px; padding: 12px;")
            self.log_detail_form.addRow(title_label, label_widget)
        
        scroll.setWidget(self.log_detail_widget)
        detail_layout.addWidget(scroll)
        
        # Add detail panel to RIGHT side (30% width)
        content_layout.addWidget(detail_frame, 3)
        
        # Add horizontal content to main layout
        main_layout.addWidget(content_frame, 1)
        
        # Footer stats
        footer_frame = QFrame()
        footer_frame.setStyleSheet("""
            QFrame {
                background-color: #f9f9f9;
                border-radius: 6px;
                border: 1px solid #e0e0e0;
            }
        """)
        footer_layout = QHBoxLayout(footer_frame)
        footer_layout.setContentsMargins(15, 10, 15, 10)
        
        self.lbl_total_logs = QLabel("Total Logs: 0")
        self.lbl_total_logs.setFont(QFont("Arial", 11, QFont.Bold))
        self.lbl_total_logs.setStyleSheet("color: #32b8c6;")
        footer_layout.addWidget(self.lbl_total_logs)
        
        footer_layout.addWidget(QLabel("|"))
        
        self.lbl_critical_logs = QLabel("Critical: 0")
        self.lbl_critical_logs.setFont(QFont("Arial", 11, QFont.Bold))
        self.lbl_critical_logs.setStyleSheet("color: #e74c3c;")
        footer_layout.addWidget(self.lbl_critical_logs)
        
        footer_layout.addWidget(QLabel("|"))
        
        self.lbl_warning_logs = QLabel("Warnings: 0")
        self.lbl_warning_logs.setFont(QFont("Arial", 11, QFont.Bold))
        self.lbl_warning_logs.setStyleSheet("color: #f39c12;")
        footer_layout.addWidget(self.lbl_warning_logs)
        
        footer_layout.addStretch()
        
        self.lbl_last_modified = QLabel("Last Modified: Never")
        self.lbl_last_modified.setFont(QFont("Arial", 10))
        self.lbl_last_modified.setStyleSheet("color: #888;")
        footer_layout.addWidget(self.lbl_last_modified)
        
        main_layout.addWidget(footer_frame)
        
        # Store all logs for filtering
        self.all_logs = []
        
        # Load logs on startup
        self._load_all_logs()
        
        return widget
    
    def _create_settings_tab(self):
        """Settings tab."""
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        layout = QVBoxLayout(scroll_widget)
        layout.setSpacing(15)
        
        # Config
        config_group = QGroupBox("📂 CONFIGURATION MANAGEMENT")
        config_form = QHBoxLayout(config_group)
        self.btn_load = QPushButton("📥 Load Config")
        self.btn_load.clicked.connect(self._load_config_dialog)
        config_form.addWidget(self.btn_load)
        self.btn_save = QPushButton("💾 Save Config")
        self.btn_save.clicked.connect(self._save_config_dialog)
        config_form.addWidget(self.btn_save)
        config_form.addStretch()
        layout.addWidget(config_group)
        
        # Detection
        detection_group = QGroupBox("🔍 DETECTION SETTINGS")
        detection_form = QFormLayout(detection_group)
        self.spin_burst = QSpinBox()
        self.spin_burst.setMinimum(10)
        self.spin_burst.setMaximum(500)
        self.spin_burst.setValue(self.config['detection']['burst_threshold']['file_changes_per_window'])
        detection_form.addRow("Burst Threshold (files/10s):", self.spin_burst)
        self.spin_window = QSpinBox()
        self.spin_window.setMinimum(1)
        self.spin_window.setMaximum(60)
        self.spin_window.setValue(self.config['detection']['burst_threshold']['time_window_seconds'])
        detection_form.addRow("Time Window (seconds):", self.spin_window)
        layout.addWidget(detection_group)
        
        # Risk
        risk_group = QGroupBox("⚠️ RISK SCORING")
        risk_form = QFormLayout(risk_group)
        self.spin_risk_threshold = QSpinBox()
        self.spin_risk_threshold.setMinimum(50)
        self.spin_risk_threshold.setMaximum(200)
        self.spin_risk_threshold.setValue(self.config['risk_scoring']['mitigation_threshold'])
        risk_form.addRow("Mitigation Threshold:", self.spin_risk_threshold)
        self.spin_decay = QSpinBox()
        self.spin_decay.setMinimum(1)
        self.spin_decay.setMaximum(20)
        self.spin_decay.setValue(int(self.config['risk_scoring']['score_decay_per_minute']))
        risk_form.addRow("Decay Rate (pts/min):", self.spin_decay)
        layout.addWidget(risk_group)
        
        # Features
        features_group = QGroupBox("✨ FEATURES")
        features_form = QVBoxLayout(features_group)
        self.check_canary = QCheckBox("Enable Canary Files")
        self.check_canary.setChecked(self.config['canary']['enabled'])
        features_form.addWidget(self.check_canary)
        self.check_burst = QCheckBox("Enable Burst Detection")
        self.check_burst.setChecked(True)
        features_form.addWidget(self.check_burst)
        self.check_backup = QCheckBox("Enable Backup Deletion Detection")
        self.check_backup.setChecked(True)
        features_form.addWidget(self.check_backup)
        layout.addWidget(features_group)
        
        # UI Settings: Tab size toggle
        tabsize_group = QGroupBox("🧩 UI Settings")
        tabsize_form = QFormLayout(tabsize_group)
        self.combo_tab_size = QComboBox()
        self.combo_tab_size.addItems(["Compact", "Large"])
        self.combo_tab_size.setCurrentText("Large")
        self.combo_tab_size.currentTextChanged.connect(self._on_tab_size_changed)
        tabsize_form.addRow("Tab Size:", self.combo_tab_size)
        layout.addWidget(tabsize_group)

        self.btn_apply = QPushButton("✓ APPLY SETTINGS")
        self.btn_apply.setMinimumHeight(40)
        self.btn_apply.clicked.connect(self._apply_settings)
        layout.addWidget(self.btn_apply)
        
        layout.addStretch()
        scroll.setWidget(scroll_widget)
        main_layout = QVBoxLayout(widget)
        main_layout.addWidget(scroll)
        return widget
    
    def _create_about_tab(self):
        """About tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setStyleSheet("background-color: white; border: 1px solid #ddd;")
        text.setText("""
<h2>🛡️ Ransomware Defense Kit v2.0</h2>
<p><b>Purpose:</b> Cross-platform early detection and mitigation of ransomware threats</p>
<h3>🔍 Detection Methods:</h3>
<ul>
  <li><b>Canary Files:</b> Hidden decoy files with hash verification</li>
  <li><b>Burst Activity:</b> Abnormal file modification rate detection</li>
  <li><b>Backup Deletion:</b> Suspicious command monitoring</li>
</ul>
<h3>⚙️ Operational Modes:</h3>
<ul>
  <li><b>Monitor-Only:</b> Logs all events</li>
  <li><b>Auto-Mitigate:</b> Terminates flagged processes</li>
</ul>
<h3>⚠️ Security Notes:</h3>
<ul>
  <li>Test ONLY in isolated VMs</li>
  <li>Use non-critical test data</li>
  <li>Not a replacement for backups</li>
</ul>
<p><b>Version:</b> 1.0.0 | MIT License | Author: Nady Emad</p>
        """)
        layout.addWidget(text)
        return widget
    
    def _toggle_monitoring(self):
        """Start/stop monitoring."""
        if not self.is_monitoring:
            if self.use_advanced_mode:
                # Use v2.0 Advanced Multi-Engine System (5 engines)
                self.advanced_monitor_worker = AdvancedMonitorWorker(self.config, self.logger)
                self.monitor_thread = QThread()
                self.advanced_monitor_worker.moveToThread(self.monitor_thread)
                self.advanced_monitor_worker.event_detected.connect(self._on_advanced_event_detected)
                self.advanced_monitor_worker.threat_detected.connect(self._on_advanced_threat_detected)
                self.advanced_monitor_worker.status_updated.connect(self._on_advanced_status_updated)
                self.monitor_thread.started.connect(self.advanced_monitor_worker.run)
                self.monitor_thread.start()
            else:
                # Fall back to v1.0 Legacy System
                self.monitor_worker = MonitorWorker(self.config, self.risk_engine, self.logger)
                self.monitor_thread = QThread()
                self.monitor_worker.moveToThread(self.monitor_thread)
                self.monitor_worker.event_detected.connect(self._on_event_detected)
                self.monitor_worker.risk_updated.connect(self._on_risk_updated)
                self.monitor_worker.critical_alert.connect(self._on_critical_alert)
                self.monitor_thread.started.connect(self.monitor_worker.run)
                self.monitor_thread.start()

            # Start performance monitoring
            if not self.perf_worker:
                self.perf_worker = PerformanceWorker(refresh_interval=0.5)
                self.perf_thread = QThread()
                self.perf_worker.moveToThread(self.perf_thread)
                self.perf_worker.metrics_updated.connect(self._on_perf_metrics_updated)
                self.perf_worker.error_occurred.connect(self._on_perf_error)
                self.perf_thread.started.connect(self.perf_worker.run)
                self.perf_thread.start()
            
            self.is_monitoring = True
            self.btn_start_stop.setText("⏹ STOP MONITORING")
            self.btn_start_stop.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLOR_CRITICAL};
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 6px;
                    font-weight: bold;
                }}
                QPushButton:hover {{ background-color: #A93226; }}
            """)
            mode_label = "Advanced v2.0" if self.use_advanced_mode else "Legacy v1.0"
            self.lbl_status.setText(f"🟢 MONITORING ACTIVE ({mode_label})")
            self.lbl_status.setStyleSheet("color: #27ae60; padding: 5px; font-weight: bold;")
        else:
            # Stop current monitoring worker
            if self.use_advanced_mode:
                if self.advanced_monitor_worker:
                    self.advanced_monitor_worker.stop()
            else:
                if self.monitor_worker:
                    self.monitor_worker.stop()
            
            if self.monitor_thread:
                self.monitor_thread.quit()
                self.monitor_thread.wait()

            # Stop performance monitoring
            if self.perf_worker:
                self.perf_worker.stop()
                self.perf_worker = None
            if self.perf_thread:
                self.perf_thread.quit()
                self.perf_thread.wait()
                self.perf_thread = None
            
            self.is_monitoring = False
            self.btn_start_stop.setText("▶ START MONITORING")
            self.btn_start_stop.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLOR_SUCCESS};
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 6px;
                    font-weight: bold;
                }}
                QPushButton:hover {{ background-color: #229954; }}
            """)
            self.lbl_status.setText("🔴 STOPPED")
            self.lbl_status.setStyleSheet("color: #e74c3c; padding: 5px; font-weight: bold;")
    
    def _on_mode_changed(self, mode_text):
        """Handle mode change."""
        self.current_mode = "auto-mitigate" if mode_text == "Auto-Mitigate" else "monitor-only"
        self.config['mitigation']['mode'] = self.current_mode
        self.lbl_mode_display.setText(mode_text)
    
    def _on_event_detected(self, event_dict):
        """New event detected - add to table."""
        self.live_events.append(event_dict)
        
        row = self.table_events.rowCount()
        self.table_events.insertRow(row)
        
        # Timestamp
        self.table_events.setItem(row, 0, QTableWidgetItem(
            event_dict.get('timestamp', '')[:19]
        ))
        
        # Severity with color
        severity = event_dict.get('severity', 'INFO')
        severity_item = QTableWidgetItem(severity)
        severity_item.setFont(QFont("Arial", 11, QFont.Bold))
        
        if severity == 'CRITICAL':
            severity_item.setBackground(QColor(231, 76, 60))
            severity_item.setForeground(QColor(0, 0, 0))
        elif severity == 'WARNING':
            severity_item.setBackground(QColor(243, 156, 18))
            severity_item.setForeground(QColor(0, 0, 0))
        else:
            severity_item.setBackground(QColor(52, 152, 219))
            severity_item.setForeground(QColor(0, 0, 0))
        
        self.table_events.setItem(row, 1, severity_item)
        
        # Rule
        self.table_events.setItem(row, 2, QTableWidgetItem(
            event_dict.get('rule', '')
        ))
        
        # File Path (safe for None)
        path_val = event_dict.get('path') or ''
        self.table_events.setItem(row, 3, QTableWidgetItem(str(path_val)[:80]))
        
        # PID
        pid_val = event_dict.get('pid')
        self.table_events.setItem(row, 4, QTableWidgetItem(str(pid_val) if pid_val is not None else ''))
        
        # Process Name
        proc_val = event_dict.get('process_name') or ''
        self.table_events.setItem(row, 5, QTableWidgetItem(str(proc_val)))
        
        # Action
        action_val = event_dict.get('action') or 'Logged'
        self.table_events.setItem(row, 6, QTableWidgetItem(str(action_val)))
        
        # Set row height for consistency
        self.table_events.setRowHeight(row, 35)
        
        self.table_events.scrollToBottom()
        self._update_summary()

    def _on_event_row_selected(self):
        """Handle row selection - show event details in right panel."""
        selected_rows = self.table_events.selectionModel().selectedRows()
        
        if not selected_rows:
            return
        
        row_idx = selected_rows[0].row()
        
        if row_idx >= 0 and row_idx < len(self.live_events):
            event = self.live_events[row_idx]
            
            # Helper function for consistent field styling
            def set_detail_field(key, raw_value, is_severity=False):
                widget = self.detail_labels[key][1]
                value = str(raw_value) if raw_value else 'N/A'
                widget.setText(value)
                
                if is_severity:
                    if value == 'CRITICAL':
                        widget.setStyleSheet("color: #fff; padding: 10px; background: #e74c3c; border-radius: 4px; font-weight: bold;")
                    elif value == 'WARNING':
                        widget.setStyleSheet("color: #000; padding: 10px; background: #f39c12; border-radius: 4px; font-weight: bold;")
                    else:
                        widget.setStyleSheet("color: #fff; padding: 10px; background: #32b8c6; border-radius: 4px; font-weight: bold;")
                else:
                    widget.setStyleSheet("color: #555; padding: 10px; background: #f9f9f9; border-radius: 4px; min-height: 30px;")
            
            # Populate fields
            set_detail_field('timestamp', event.get('timestamp', 'N/A')[:19])
            set_detail_field('severity', event.get('severity', 'INFO'), is_severity=True)
            set_detail_field('rule', event.get('rule', 'N/A'))
            set_detail_field('path', event.get('path', 'N/A'))
            set_detail_field('pid', event.get('pid', 'N/A'))
            set_detail_field('process_name', event.get('process_name', 'N/A'))
            set_detail_field('action', event.get('action', 'N/A'))
            set_detail_field('message', event.get('message', 'N/A'))
    
    def _on_risk_updated(self, risk_score, flagged_processes):
        """Risk score updated."""
        self.risk_progress.setValue(int(risk_score))
        self.lbl_risk_text.setText(f"{int(risk_score)} / 200")
        
        # Determine risk level and colors
        if risk_score < 50:
            color = "#27ae60"
            chunk_color = "#27ae60"
            status_text = "🟢 Safe - No threats detected"
            bg_color = "#f0f9f8"
        elif risk_score < 120:
            color = "#f39c12"
            chunk_color = "#f39c12"
            status_text = "🟡 Medium Risk - Monitor activity"
            bg_color = "#fff3e0"
        else:
            color = "#e74c3c"
            chunk_color = "#e74c3c"
            status_text = "🔴 High Risk - Action recommended"
            bg_color = "#ffe6e6"
        
        self.risk_progress.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid #ddd;
                border-radius: 8px;
                background-color: #f5f5f5;
                height: 35px;
            }}
            QProgressBar::chunk {{
                background-color: {chunk_color};
                border-radius: 6px;
            }}
        """)
        self.lbl_risk_text.setStyleSheet(f"color: {color}; padding: 10px; background: {bg_color}; border-radius: 6px; font-weight: bold; text-align: center;")
        self.lbl_risk_status.setText(status_text)
        self.lbl_risk_status.setStyleSheet(f"color: {color}; padding: 8px; font-weight: 500;")
        
        self.flagged_processes = flagged_processes
        self.lbl_flagged.setText(", ".join(flagged_processes) if flagged_processes else "None")
    
    def _on_critical_alert(self, alert_message, event_data=None):
        """Critical alert dialog with Block/Allow actions."""
        # If event_data not provided, try to get from live_events
        if not event_data:
            for event in reversed(self.live_events):
                if event.get('severity') in ['CRITICAL', 'WARNING']:
                    event_data = event
                    break
        
        # Check whitelist/blacklist before showing dialog
        if event_data:
            process_name = event_data.get('process_name', '').lower()
            pid = event_data.get('pid')
            
            # Check blacklist - auto-block
            if self._is_blacklisted(process_name, pid):
                QMessageBox.warning(
                    self,
                    "🚫 Blocked (Blacklisted)",
                    f"Process '{process_name}' (PID: {pid}) is blacklisted.\n\n"
                    f"Action: Automatically blocked."
                )
                return
            
            # Check whitelist - auto-allow
            if self._is_whitelisted(process_name, pid):
                return  # Silently allow
        
        # Show dialog with Block/Allow/Acknowledge options
        dialog = CriticalAlertDialog(
            "⚠️ CRITICAL THREAT DETECTED",
            alert_message,
            event_data=event_data,
            parent=self
        )
        
        # Process user action
        if dialog.user_action == 'block' and event_data:
            self._add_to_blacklist(event_data)
            QMessageBox.information(
                self,
                "🚫 Blacklisted",
                f"Process '{event_data.get('process_name')}' (PID: {event_data.get('pid')}) "
                f"has been added to the blacklist.\n\n"
                f"Future detections will be automatically blocked."
            )
        elif dialog.user_action == 'allow' and event_data:
            self._add_to_whitelist(event_data)
            QMessageBox.information(
                self,
                "✅ Whitelisted",
                f"Process '{event_data.get('process_name')}' (PID: {event_data.get('pid')}) "
                f"has been added to the whitelist.\n\n"
                f"Future detections will be automatically allowed."
            )
    
    def _decay_risk(self):
        """Decay risk over time."""
        self.risk_engine.decay_score()
        self.lbl_risk_text.setText(f"{int(self.risk_engine.current_score)} / 200")
    
    def _update_dirs_label(self):
        """Update monitored dirs."""
        dirs = self.config['monitoring']['directories']
        if not dirs:
            self.lbl_dirs.setText("No directories configured")
            return
        text = "<br>".join([f"• {d}" for d in dirs[:4]])
        if len(dirs) > 4:
            text += f"<br>... and {len(dirs) - 4} more"
        self.lbl_dirs.setText(text)
    
    def _load_list(self, filepath):
        """Load whitelist or blacklist from JSON file."""
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading {filepath}: {e}")
                return []
        return []
    
    def _save_list(self, filepath, data):
        """Save whitelist or blacklist to JSON file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving {filepath}: {e}")
    
    def _is_whitelisted(self, process_name, pid):
        """Check if process is in whitelist."""
        process_name = process_name.lower() if process_name else ''
        for entry in self.whitelist:
            if entry.get('process_name', '').lower() == process_name:
                return True
        return False
    
    def _is_blacklisted(self, process_name, pid):
        """Check if process is in blacklist."""
        process_name = process_name.lower() if process_name else ''
        for entry in self.blacklist:
            if entry.get('process_name', '').lower() == process_name:
                return True
        return False
    
    def _add_to_whitelist(self, event_data):
        """Add process to whitelist."""
        entry = {
            'process_name': event_data.get('process_name', ''),
            'pid': event_data.get('pid'),
            'path': event_data.get('path', ''),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reason': f"User whitelisted from rule: {event_data.get('rule', 'N/A')}"
        }
        
        # Avoid duplicates
        if not self._is_whitelisted(entry['process_name'], entry['pid']):
            self.whitelist.append(entry)
            self._save_list(self.whitelist_path, self.whitelist)
    
    def _add_to_blacklist(self, event_data):
        """Add process to blacklist."""
        entry = {
            'process_name': event_data.get('process_name', ''),
            'pid': event_data.get('pid'),
            'path': event_data.get('path', ''),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reason': f"User blacklisted from rule: {event_data.get('rule', 'N/A')}"
        }
        
        # Avoid duplicates
        if not self._is_blacklisted(entry['process_name'], entry['pid']):
            self.blacklist.append(entry)
            self._save_list(self.blacklist_path, self.blacklist)
    
    def _update_summary(self):
        """Update event counts."""
        total = len(self.live_events)
        critical = sum(1 for e in self.live_events if e.get('severity') == 'CRITICAL')
        warning = sum(1 for e in self.live_events if e.get('severity') == 'WARNING')
        info = total - critical - warning
        
        self.lbl_total_events.setText(str(total))
        self.lbl_critical_events.setText(str(critical))
        self.lbl_warning_events.setText(str(warning))
        self.lbl_info_events.setText(str(info))
        
        # Update Live Events tab footer
        if hasattr(self, 'lbl_event_count') and hasattr(self, 'lbl_last_event'):
            self.lbl_event_count.setText(f"Total Events: {total}")
            if self.live_events:
                last_event = self.live_events[-1]
                timestamp = last_event.get('timestamp', '')[:19]
                rule = last_event.get('rule', 'UNKNOWN')
                self.lbl_last_event.setText(f"Last Event: {timestamp} - {rule}")
            else:
                self.lbl_last_event.setText("No events yet")
    
    def _update_status_bar(self):
        """Update status bar."""
        status = "🟢 MONITORING" if self.is_monitoring else "🔴 STOPPED"
        msg = f"{status} | Mode: {self.combo_mode.currentText()} | Events: {len(self.live_events)}"
        self.status_label.setText(msg)

    def _load_all_logs(self):
        """Load all logs from JSONL file."""
        self.table_logs.setRowCount(0)
        self.all_logs = []
        try:
            jsonl_file = self.config['logging']['jsonl_file']
            if not os.path.exists(jsonl_file):
                self.lbl_total_logs.setText("Total Logs: 0 (file not found)")
                return
            with open(jsonl_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        self.all_logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue
            self._display_logs(self.all_logs)
            total = len(self.all_logs)
            critical = sum(1 for l in self.all_logs if l.get('severity') == 'CRITICAL')
            warning = sum(1 for l in self.all_logs if l.get('severity') == 'WARNING')
            self.lbl_total_logs.setText(f"Total Logs: {total}")
            self.lbl_critical_logs.setText(f"Critical: {critical}")
            self.lbl_warning_logs.setText(f"Warnings: {warning}")
            mtime = os.path.getmtime(jsonl_file)
            mod_time = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            self.lbl_last_modified.setText(f"Last Modified: {mod_time}")
        except Exception as e:
            if hasattr(self, 'log_detail_labels'):
                self.log_detail_labels['message'][1].setText(f"Error loading logs: {str(e)}")

    def _display_logs(self, logs):
        """Display logs in table with proper styling."""
        self.table_logs.setRowCount(0)

        # Update footer counters (total vs shown)
        total_all = len(self.all_logs)
        total_shown = len(logs)
        critical_all = sum(1 for l in self.all_logs if l.get('severity') == 'CRITICAL')
        warning_all = sum(1 for l in self.all_logs if l.get('severity') == 'WARNING')
        self.lbl_total_logs.setText(f"Total Logs: {total_all} | Shown: {total_shown}")
        self.lbl_critical_logs.setText(f"Critical: {critical_all}")
        self.lbl_warning_logs.setText(f"Warnings: {warning_all}")
        
        for log in logs:
            row = self.table_logs.rowCount()
            self.table_logs.insertRow(row)
            
            # Timestamp
            timestamp_item = QTableWidgetItem(log.get('timestamp', '')[:19])
            timestamp_item.setFont(QFont("Arial", 10))
            self.table_logs.setItem(row, 0, timestamp_item)
            
            # Severity with COLOR (THIS WAS MISSING)
            severity = log.get('severity', 'INFO')
            severity_item = QTableWidgetItem(severity)
            severity_item.setFont(QFont("Arial", 11, QFont.Bold))
            
            if severity == 'CRITICAL':
                severity_item.setBackground(QColor(231, 76, 60))
                severity_item.setForeground(QColor(0, 0, 0))
            elif severity == 'WARNING':
                severity_item.setBackground(QColor(243, 156, 18))
                severity_item.setForeground(QColor(0, 0, 0))
            else:
                severity_item.setBackground(QColor(52, 152, 219))
                severity_item.setForeground(QColor(0, 0, 0))
            
            self.table_logs.setItem(row, 1, severity_item)
            
            # Rule
            rule_item = QTableWidgetItem(log.get('rule', 'N/A'))
            rule_item.setFont(QFont("Arial", 10))
            self.table_logs.setItem(row, 2, rule_item)
            
            # File Path
            path_val = log.get('path') or 'N/A'
            path_item = QTableWidgetItem(str(path_val)[:80])
            path_item.setFont(QFont("Arial", 10))
            self.table_logs.setItem(row, 3, path_item)
            
            # PID
            pid_item = QTableWidgetItem(str(log.get('pid', 'N/A')))
            pid_item.setFont(QFont("Arial", 10))
            self.table_logs.setItem(row, 4, pid_item)
            
            # Process
            process_item = QTableWidgetItem(log.get('process_name', 'N/A'))
            process_item.setFont(QFont("Arial", 10))
            self.table_logs.setItem(row, 5, process_item)
            
            # Action
            action_item = QTableWidgetItem(log.get('action', 'Logged'))
            action_item.setFont(QFont("Arial", 10))
            self.table_logs.setItem(row, 6, action_item)
            
            # Message
            message_item = QTableWidgetItem(log.get('message', 'N/A')[:100])
            message_item.setFont(QFont("Arial", 10))
            self.table_logs.setItem(row, 7, message_item)
            
            self.table_logs.setRowHeight(row, 35)

    def _filter_logs_table(self):
        """Filter logs by severity and search text."""
        severity_filter = self.combo_severity_filter.currentText()
        search_text = self.search_logs.text().lower()
        filtered_logs = [
            log for log in self.all_logs
            if (severity_filter == 'All' or log.get('severity') == severity_filter)
            and (
                not search_text
                or search_text in log.get('rule', '').lower()
                or search_text in log.get('path', '').lower()
                or search_text in log.get('process_name', '').lower()
                or search_text in log.get('message', '').lower()
            )
        ]
        self._display_logs(filtered_logs)

    def _on_log_row_selected(self):
        """Show selected log details in form layout."""
        selected_rows = self.table_logs.selectionModel().selectedRows()
        
        if not selected_rows:
            # Clear detail panel
            for _, label_widget in self.log_detail_labels.values():
                label_widget.setText('N/A')
            return
        
        row_idx = selected_rows[0].row()
        
        if row_idx >= 0 and row_idx < len(self.all_logs):
            log = self.all_logs[row_idx]
            
            # Helper function to set field with consistent styling
            def set_detail_field(key, raw_value, is_severity=False):
                widget = self.log_detail_labels[key][1]
                value = str(raw_value) if raw_value else 'N/A'
                widget.setText(value)
                
                if is_severity:
                    if value == 'CRITICAL':
                        widget.setStyleSheet("color: #fff; padding: 10px; background: #e74c3c; border-radius: 4px; font-weight: bold;")
                    elif value == 'WARNING':
                        widget.setStyleSheet("color: #000; padding: 10px; background: #f39c12; border-radius: 4px; font-weight: bold;")
                    else:
                        widget.setStyleSheet("color: #fff; padding: 10px; background: #32b8c6; border-radius: 4px; font-weight: bold;")
                else:
                    widget.setStyleSheet("color: #555; padding: 10px; background: #f9f9f9; border-radius: 4px; min-height: 30px;")
            
            # Populate fields with consistent styling
            set_detail_field('timestamp', log.get('timestamp', 'N/A')[:19])
            set_detail_field('severity', log.get('severity', 'INFO'), is_severity=True)
            set_detail_field('rule', log.get('rule', 'N/A'))
            set_detail_field('path', log.get('path', 'N/A'))
            set_detail_field('pid', log.get('pid', 'N/A'))
            set_detail_field('process_name', log.get('process_name', 'N/A'))
            set_detail_field('action', log.get('action', 'N/A'))
            set_detail_field('message', log.get('message', 'N/A'))

    def _clear_logs(self):
        """Clear all log files."""
        reply = WarningDialog(
            "Clear Logs?",
            "This will delete all log files permanently.\n\nThis action cannot be undone.\n\nAre you sure?",
            buttons=[("Clear All Logs", 1), ("Cancel", 0)],
            parent=self
        )
        if reply.result_value == 1:
            try:
                jsonl_file = self.config['logging']['jsonl_file']
                csv_file = self.config['logging']['csv_file']
                if os.path.exists(jsonl_file):
                    os.remove(jsonl_file)
                if os.path.exists(csv_file):
                    os.remove(csv_file)
                self._load_all_logs()
                SuccessDialog("✓ Logs Cleared", "All log files have been successfully cleared!", parent=self)
            except Exception as e:
                WarningDialog("❌ Error", f"Failed to clear logs:\n{str(e)}", parent=self)
    
    def _apply_settings(self):
        """Apply settings."""
        self.config['detection']['burst_threshold']['file_changes_per_window'] = self.spin_burst.value()
        self.config['detection']['burst_threshold']['time_window_seconds'] = self.spin_window.value()
        self.config['risk_scoring']['mitigation_threshold'] = self.spin_risk_threshold.value()
        self.config['risk_scoring']['score_decay_per_minute'] = self.spin_decay.value()
        self.config['canary']['enabled'] = self.check_canary.isChecked()
        SuccessDialog("✓ Settings Applied", "Settings have been applied successfully!", parent=self)
        self._show_toast("Settings applied", severity="SUCCESS")
    
    def _load_config_dialog(self):
        """Load configuration."""
        path, _ = QFileDialog.getOpenFileName(self, "Load Config", "", "JSON (*.json);;YAML (*.yaml *.yml)")
        if path:
            try:
                self.config = self.config_loader.load(path)
                self._update_dirs_label()
                SuccessDialog("✓ Config Loaded", f"Configuration has been loaded from:\n{path}", parent=self)
            except Exception as e:
                WarningDialog("❌ Load Error", f"Failed to load configuration:\n{str(e)}", parent=self)
    
    def _save_config_dialog(self):
        """Save configuration."""
        path, _ = QFileDialog.getSaveFileName(self, "Save Config", "config.json", "JSON (*.json)")
        if path:
            try:
                with open(path, 'w') as f:
                    json.dump(self.config, f, indent=2)
                SuccessDialog("✓ Config Saved", f"Configuration has been saved to:\n{path}", parent=self)
            except Exception as e:
                WarningDialog("❌ Save Error", f"Failed to save configuration:\n{str(e)}", parent=self)
    
    def _export_logs(self):
        """Export logs."""
        path, _ = QFileDialog.getSaveFileName(self, "Export Logs", "export.zip", "ZIP (*.zip)")
        if path:
            try:
                import shutil
                shutil.make_archive(path.replace('.zip', ''), 'zip', 'logs')
                SuccessDialog("✓ Export Complete", f"Logs have been exported to:\n{path}", parent=self)
                self._show_toast("Logs exported", severity="SUCCESS")
            except Exception as e:
                WarningDialog("❌ Export Error", f"Failed to export logs:\n{str(e)}", parent=self)
                self._show_toast("Export failed", severity="CRITICAL")

    def _test_demo_event(self):
        """Test: Manually add a demo event to the table."""
        demo_event = {
            'timestamp': datetime.now().isoformat(),
            'severity': 'WARNING',
            'rule': 'BURST_ACTIVITY_DETECTED',
            'path': 'C:\\Users\\Test\\Documents\\important.docx',
            'pid': '4856',
            'process_name': 'winword.exe',
            'action': 'Logged'
        }
        self._on_event_detected(demo_event)
        SuccessDialog("✓ Demo Event Added", "A test event has been added to the Live Events table.", parent=self)
        self._show_toast("Demo event added", severity="INFO")
    
    # ===== ADVANCED v2.0 EVENT HANDLERS (5-Engine System) =====
    
    def _on_advanced_event_detected(self, event_dict):
        """Handle advanced engine event detection."""
        # Normalize advanced events to legacy schema so UI stays consistent
        normalized = {
            'timestamp': event_dict.get('timestamp', datetime.now().isoformat()),
            'severity': event_dict.get('severity', 'INFO'),
            'rule': event_dict.get('rule', event_dict.get('engine', 'ADVANCED_EVENT')),
            'path': event_dict.get('path', event_dict.get('triggered_by', 'N/A')),
            'pid': event_dict.get('pid', ''),
            'process_name': event_dict.get('process_name', ''),
            'action': event_dict.get('action', event_dict.get('recommended_action', 'Logged')),
            'message': event_dict.get('message', ''),
        }
        self._on_event_detected(normalized)
    
    def _on_advanced_threat_detected(self, threat_dict):
        """Handle advanced engine threat detection (high-severity events)."""
        threat_level = threat_dict.get('threat_level', 'MEDIUM')
        composite_score = threat_dict.get('composite_score', 0)
        recommended_action = threat_dict.get('recommended_action', 'MONITOR')
        
        # Convert threat level to severity for logging
        severity_map = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'WARNING',
            'MEDIUM': 'WARNING',
            'LOW': 'INFO',
            'INFO': 'INFO'
        }
        
        severity = severity_map.get(threat_level, 'WARNING')
        
        # Log the threat
        threat_event = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'rule': f'ADVANCED_{threat_level}_THREAT',
            'path': threat_dict.get('triggered_by', 'N/A'),
            'pid': threat_dict.get('pid', 'N/A'),
            'process_name': threat_dict.get('process_name', 'N/A'),
            'action': recommended_action,
            'message': f'Composite Score: {composite_score:.0f}, Action: {recommended_action}'
        }
        
        self.logger.log_event(threat_event)
        self._on_event_detected(threat_event)
        
        # Show critical alert if needed
        if threat_level == 'CRITICAL':
            alert_msg = f"""
Advanced Threat Detection Alert!

Threat Level: {threat_level}
Composite Score: {composite_score:.0f}/100
Recommended Action: {recommended_action}

Triggered by: {threat_dict.get('triggered_by', 'N/A')}
Process: {threat_dict.get('process_name', 'N/A')} (PID: {threat_dict.get('pid', 'N/A')})
            """
            self._on_critical_alert(alert_msg)
    
    def _on_advanced_status_updated(self, status_message):
        """Handle advanced engine status updates."""
        # Update status bar or log if needed
        if hasattr(self, 'status_label'):
            pass  # Could update here if needed
    
    # ===== END ADVANCED v2.0 HANDLERS =====

    def _on_perf_metrics_updated(self, metrics):
        """Update performance metrics display."""
        if not self.perf_labels:
            return

        try:
            # CPU metrics
            cpu = metrics.get('cpu', {}) or {}
            cpu_percent = cpu.get('overall_percent', 0) or 0
            
            # Update CPU KPI card
            if 'cpu_card' in self.perf_labels:
                self.perf_labels['cpu_card'].setText(f"{cpu_percent:.0f}%")
            
            if 'cpu_bar' in self.perf_labels:
                self.perf_labels['cpu_bar'].setValue(int(cpu_percent))
            if 'cpu_text' in self.perf_labels:
                self.perf_labels['cpu_text'].setText(f"{cpu_percent:.1f}%")

            cores = cpu.get('core_count', 0) or 0
            if 'cpu_cores' in self.perf_labels:
                self.perf_labels['cpu_cores'].setText(f"{cores} cores")

            freq_raw = cpu.get('frequency', 0) or 0
            freq_ghz = freq_raw / 1000 if freq_raw else 0
            if 'cpu_freq' in self.perf_labels:
                self.perf_labels['cpu_freq'].setText(f"{freq_ghz:.2f} GHz")

            temp = cpu.get('temperature', 0) or 0
            if 'cpu_temp' in self.perf_labels:
                if temp > 0:
                    self.perf_labels['cpu_temp'].setText(f"{temp:.1f}°C")
                    if temp > 80:
                        self.perf_labels['cpu_temp'].setStyleSheet("color: #e74c3c; padding: 8px; background: #ffe6e6; border-radius: 4px; font-weight: bold;")
                    elif temp > 60:
                        self.perf_labels['cpu_temp'].setStyleSheet("color: #f39c12; padding: 8px; background: #fff3e0; border-radius: 4px;")
                    else:
                        self.perf_labels['cpu_temp'].setStyleSheet("color: #27ae60; padding: 8px; background: #f0f9f8; border-radius: 4px;")
                else:
                    self.perf_labels['cpu_temp'].setText("N/A")
                    self.perf_labels['cpu_temp'].setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")

            # Memory metrics
            memory = metrics.get('memory', {}) or {}
            mem_percent = memory.get('percent', 0) or 0
            
            # Update Memory KPI card
            if 'mem_card' in self.perf_labels:
                self.perf_labels['mem_card'].setText(f"{mem_percent:.0f}%")
            
            if 'mem_bar' in self.perf_labels:
                self.perf_labels['mem_bar'].setValue(int(mem_percent))
            if 'mem_text' in self.perf_labels:
                self.perf_labels['mem_text'].setText(f"{mem_percent:.1f}%")

            total_mb = (memory.get('total', 0) or 0) / (1024 ** 3)
            used_mb = (memory.get('used', 0) or 0) / (1024 ** 3)
            avail_mb = (memory.get('available', 0) or 0) / (1024 ** 3)
            if 'mem_total' in self.perf_labels:
                self.perf_labels['mem_total'].setText(f"{total_mb:.1f} GB")
            if 'mem_used' in self.perf_labels:
                self.perf_labels['mem_used'].setText(f"{used_mb:.1f} GB")
            if 'mem_available' in self.perf_labels:
                self.perf_labels['mem_available'].setText(f"{avail_mb:.1f} GB")

            # Disk metrics
            disk = metrics.get('disk', {}) or {}
            partitions = disk.get('partitions', []) or []
            avg_disk_percent = disk.get('average_percent', 0) or 0
            
            # Update Disk KPI card with average
            if 'disk_card' in self.perf_labels:
                self.perf_labels['disk_card'].setText(f"{avg_disk_percent:.0f}%")
            
            if 'disk_bar' in self.perf_labels:
                self.perf_labels['disk_bar'].setValue(int(avg_disk_percent))
            if 'disk_text' in self.perf_labels:
                self.perf_labels['disk_text'].setText(f"{avg_disk_percent:.1f}%")
            
            # Use primary partition for details
            if partitions and isinstance(partitions, list) and len(partitions) > 0:
                p = partitions[0]
                total_gb = (p.get('total', 0) or 0) / (1024 ** 3)
                used_gb = (p.get('used', 0) or 0) / (1024 ** 3)
                free_gb = (p.get('free', 0) or 0) / (1024 ** 3)

                if 'disk_total' in self.perf_labels:
                    self.perf_labels['disk_total'].setText(f"{total_gb:.1f} GB")
                if 'disk_used' in self.perf_labels:
                    self.perf_labels['disk_used'].setText(f"{used_gb:.1f} GB")
                if 'disk_free' in self.perf_labels:
                    self.perf_labels['disk_free'].setText(f"{free_gb:.1f} GB")
            elif partitions and isinstance(partitions, dict):
                # If partitions is a dict, get first value
                partition_list = list(partitions.values())
                if partition_list:
                    p = partition_list[0]
                    total_gb = (p.get('total', 0) or 0) / (1024 ** 3)
                    used_gb = (p.get('used', 0) or 0) / (1024 ** 3)
                    free_gb = (p.get('free', 0) or 0) / (1024 ** 3)

                    if 'disk_total' in self.perf_labels:
                        self.perf_labels['disk_total'].setText(f"{total_gb:.1f} GB")
                    if 'disk_used' in self.perf_labels:
                        self.perf_labels['disk_used'].setText(f"{used_gb:.1f} GB")
                    if 'disk_free' in self.perf_labels:
                        self.perf_labels['disk_free'].setText(f"{free_gb:.1f} GB")

            # Top processes by CPU
            top_procs = metrics.get('top_processes', {}) or {}
            top_cpu = top_procs.get('top_cpu', []) or []
            
            # Update process count KPI card
            if 'proc_card' in self.perf_labels:
                import psutil
                proc_count = len(psutil.pids())
                self.perf_labels['proc_card'].setText(str(proc_count))
            
            if 'table_cpu' in self.perf_labels:
                table_cpu = self.perf_labels['table_cpu']
                table_cpu.setRowCount(len(top_cpu))
                for idx, proc in enumerate(top_cpu):
                    name = (proc.get('name') or 'N/A')[:30]
                    pid_val = str(proc.get('pid', ''))
                    cpu_val = f"{proc.get('cpu_percent', 0):.1f}%"
                    mem_val = f"{proc.get('memory_percent', 0):.1f}%"
                    table_cpu.setItem(idx, 0, QTableWidgetItem(name))
                    table_cpu.setItem(idx, 1, QTableWidgetItem(pid_val))
                    table_cpu.setItem(idx, 2, QTableWidgetItem(cpu_val))
                    table_cpu.setItem(idx, 3, QTableWidgetItem(mem_val))
                    table_cpu.setRowHeight(idx, 42)

            # Top processes by Memory
            top_memory = top_procs.get('top_memory', []) or []
            if 'table_memory' in self.perf_labels:
                table_mem = self.perf_labels['table_memory']
                table_mem.setRowCount(len(top_memory))
                for idx, proc in enumerate(top_memory):
                    name = (proc.get('name') or 'N/A')[:30]
                    pid_val = str(proc.get('pid', ''))
                    mem_val = f"{proc.get('memory_percent', 0):.1f}%"
                    cpu_val = f"{proc.get('cpu_percent', 0):.1f}%"
                    table_mem.setItem(idx, 0, QTableWidgetItem(name))
                    table_mem.setItem(idx, 1, QTableWidgetItem(pid_val))
                    table_mem.setItem(idx, 2, QTableWidgetItem(mem_val))
                    table_mem.setItem(idx, 3, QTableWidgetItem(cpu_val))
                    table_mem.setRowHeight(idx, 42)

            # Update status and timestamp
            if 'last_update' in self.perf_labels:
                self.perf_labels['last_update'].setText(f"Last Update: {datetime.now().strftime('%H:%M:%S')}")
            if 'status' in self.perf_labels:
                self.perf_labels['status'].setText("🟢 Performance Monitoring Active")
                self.perf_labels['status'].setStyleSheet("color: #27ae60; font-weight: bold;")
            
            # Network metrics
            network = metrics.get('network', {}) or {}
            download_rate = network.get('download_rate', 0) or 0
            upload_rate = network.get('upload_rate', 0) or 0
            total_rate = download_rate + upload_rate
            
            # Update Network KPI card
            if 'net_card' in self.perf_labels:
                if total_rate < 1024:
                    self.perf_labels['net_card'].setText(f"{total_rate:.0f} B/s")
                elif total_rate < 1024 * 1024:
                    self.perf_labels['net_card'].setText(f"{total_rate / 1024:.1f} KB/s")
                else:
                    self.perf_labels['net_card'].setText(f"{total_rate / (1024 * 1024):.1f} MB/s")
            
            # Update Network details
            if 'net_download' in self.perf_labels:
                if download_rate < 1024:
                    self.perf_labels['net_download'].setText(f"{download_rate:.0f} B/s")
                elif download_rate < 1024 * 1024:
                    self.perf_labels['net_download'].setText(f"{download_rate / 1024:.1f} KB/s")
                else:
                    self.perf_labels['net_download'].setText(f"{download_rate / (1024 * 1024):.1f} MB/s")
            
            if 'net_upload' in self.perf_labels:
                if upload_rate < 1024:
                    self.perf_labels['net_upload'].setText(f"{upload_rate:.0f} B/s")
                elif upload_rate < 1024 * 1024:
                    self.perf_labels['net_upload'].setText(f"{upload_rate / 1024:.1f} KB/s")
                else:
                    self.perf_labels['net_upload'].setText(f"{upload_rate / (1024 * 1024):.1f} MB/s")
            
            if 'net_total' in self.perf_labels:
                if total_rate < 1024:
                    self.perf_labels['net_total'].setText(f"{total_rate:.0f} B/s")
                elif total_rate < 1024 * 1024:
                    self.perf_labels['net_total'].setText(f"{total_rate / 1024:.1f} KB/s")
                else:
                    self.perf_labels['net_total'].setText(f"{total_rate / (1024 * 1024):.1f} MB/s")
            
            # GPU metrics
            gpu = metrics.get('gpu', {}) or {}
            gpu_available = gpu.get('available', False)
            
            # Update GPU KPI card
            if 'gpu_card' in self.perf_labels:
                if gpu_available:
                    gpu_load = gpu.get('load', 0) or 0
                    self.perf_labels['gpu_card'].setText(f"{gpu_load:.0f}%")
                else:
                    self.perf_labels['gpu_card'].setText("N/A")
            
            # Update GPU details
            if 'gpu_load' in self.perf_labels:
                if gpu_available:
                    gpu_load = gpu.get('load', 0) or 0
                    self.perf_labels['gpu_load'].setText(f"{gpu_load:.1f}%")
                else:
                    self.perf_labels['gpu_load'].setText("N/A")
            
            if 'gpu_temp' in self.perf_labels:
                if gpu_available:
                    gpu_temp = gpu.get('temperature', 0) or 0
                    if gpu_temp > 0:
                        self.perf_labels['gpu_temp'].setText(f"{gpu_temp:.1f}°C")
                    else:
                        self.perf_labels['gpu_temp'].setText("N/A")
                else:
                    self.perf_labels['gpu_temp'].setText("N/A")
            
            if 'gpu_status' in self.perf_labels:
                if gpu_available:
                    self.perf_labels['gpu_status'].setText("✅ Available")
                    self.perf_labels['gpu_status'].setStyleSheet("color: #27ae60; padding: 8px; background: #f0f9f8; border-radius: 4px; font-weight: bold;")
                else:
                    self.perf_labels['gpu_status'].setText("❌ Not Available")
                    self.perf_labels['gpu_status'].setStyleSheet("color: #888; padding: 8px; background: #f9f9f9; border-radius: 4px;")

        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"Error updating performance metrics: {type(e).__name__}: {str(e)}")
            print(f"Full traceback:\n{error_details}")

    def _on_perf_error(self, error_msg):
        """Handle performance monitoring error."""
        print(f"Performance monitoring error: {error_msg}")
        if 'status' in self.perf_labels:
            self.perf_labels['status'].setText("🔴 Monitoring Error")
            self.perf_labels['status'].setStyleSheet("color: #e74c3c; font-weight: bold;")

    def _on_emergency_lockdown(self):
        """Manual emergency lockdown trigger."""
        reply = WarningDialog(
            "🔴 Emergency Lockdown",
            "This will terminate suspicious processes immediately.\n\nThis action cannot be undone.\n\nAre you sure you want to proceed?",
            buttons=[("Activate Lockdown", 1), ("Cancel", 0)],
            parent=self
        )
        
        if reply.result_value != 1:
            return

        try:
            success = self.emergency_handler.initiate_emergency_lockdown("Manual activation via UI")
            if success:
                CriticalAlertDialog("🔴 EMERGENCY LOCKDOWN ACTIVATED", 
                    "Emergency lockdown has been initiated.\n\nAll suspicious processes have been terminated.\n\nSystem is now in lockdown mode.", 
                    parent=self)
                self._show_toast("Lockdown activated", severity="CRITICAL")
            else:
                WarningDialog("Lockdown Status", "Lockdown is already active or failed to start.", parent=self)
                self._show_toast("Lockdown already active or failed", severity="WARNING")
        except Exception as e:
            WarningDialog("Lockdown Error", f"Failed to start lockdown:\n{str(e)}", parent=self)
            self._show_toast("Lockdown error", severity="CRITICAL")

    def _check_defense_integrity(self):
        """Periodic self-integrity check; triggers alert/lockdown on tamper."""
        try:
            if not self.tamper_detector.check_integrity():
                alert = "🚨 DEFENSE SYSTEM TAMPERED - Initiating lockdown"
                if hasattr(self, '_on_critical_alert'):
                    self._on_critical_alert(alert)
                else:
                    QMessageBox.warning(self, "Tamper Detected", alert)
                # Auto-lockdown without prompt
                self.emergency_handler.initiate_emergency_lockdown("Tamper detected")
                self._show_toast("Defense tampered - lockdown", severity="CRITICAL")
        except Exception:
            pass
    
    def closeEvent(self, event):
        """Clean shutdown."""
        # Stop monitoring
        if self.is_monitoring:
            self._toggle_monitoring()
        
        # Stop timers
        if self.status_timer:
            self.status_timer.stop()
        if self.decay_timer:
            self.decay_timer.stop()
        
        # Force stop scanner worker if running
        if hasattr(self, 'scanner_worker'):
            try:
                if self.scanner_worker.isRunning():
                    self.scanner_worker.stop()
                    # Wait up to 3 seconds for graceful shutdown
                    if not self.scanner_worker.wait(3000):
                        # Force terminate if it doesn't stop
                        self.scanner_worker.terminate()
                        self.scanner_worker.wait(1000)
            except:
                pass
        
        event.accept()

    # ==== UI helpers ====
    def _on_tab_size_changed(self, text):
        """Adjust tab size and icon size at runtime (compact/large)."""
        if text == "Compact":
            self.tabs.setIconSize(QSize(20, 20))
            small_tabs = "QTabBar::tab { padding: 12px 28px; min-height: 36px; min-width: 120px; }"
            self.setStyleSheet(STYLESHEET + small_tabs)
        else:
            self.tabs.setIconSize(QSize(24, 24))
            self.setStyleSheet(STYLESHEET)

    def _show_toast(self, message, severity="INFO"):
        try:
            toast = Toast(parent=self, message=message, severity=severity)
            toast.show_near_parent_bottom_right()
        except Exception:
            pass
