import sys
import threading
from datetime import datetime

from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QPlainTextEdit, QMessageBox, QSizePolicy, QTabWidget,
    QLineEdit, QCheckBox, QGroupBox, QProgressBar, QScrollArea, QFrame,
    QTableWidget, QTableWidgetItem, QAbstractItemView, QFormLayout
)

from tool import RansomwareEngine
from performance_monitor import PerformanceMonitor


class LogBridge(QObject):
    def __init__(self):
        super().__init__()
    log_signal = pyqtSignal(str)


class PerfBridge(QObject):
    def __init__(self):
        super().__init__()
    perf_signal = pyqtSignal(dict)


class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.rules = [
            (('alert',), QColor('#27ae60')),
            (('modified',), QColor('#27ae60')),
            (('status',), QColor('#f1c40f')),
            (('action',), QColor('#e74c3c')),
        ]

    def highlightBlock(self, text):
        lower = text.lower()
        for keywords, color in self.rules:
            if any(k in lower for k in keywords):
                fmt = QTextCharFormat()
                fmt.setForeground(color)
                self.setFormat(0, len(text), fmt)
                break

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Ransomware Detection Tool")
        self.resize(980, 600)

        self.monitoring = False
        self.started_at = None
        self.total_logs = 0
        self.log_history = []
        self.perf_labels = {}

        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, stretch=1)

        self.dashboard_tab = QWidget()
        self.logs_tab = QWidget()
        self.performance_tab = QWidget()

        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.logs_tab, "Logs")
        self.tabs.addTab(self.performance_tab, "Performance")

        self._build_dashboard_tab()
        self._build_logs_tab()
        self._build_performance_tab()
        self._apply_theme()

        self.bridge = LogBridge()
        self.bridge.log_signal.connect(self.on_log_line)

        self.perf_bridge = PerfBridge()
        self.perf_bridge.perf_signal.connect(self._update_perf_ui)

        def log(msg: str):
            self.bridge.log_signal.emit(msg)

        self.engine = RansomwareEngine(log)

        self.ui_timer = QTimer(self)
        self.ui_timer.setInterval(500)
        self.ui_timer.timeout.connect(self.refresh_dashboard)
        self.ui_timer.start()

        # Initialize performance monitoring
        self.perf_monitor = PerformanceMonitor(update_callback=self._update_perf_callback)
        if PerformanceMonitor.is_available():
            self.perf_monitor.start()

        self.update_controls()
        self.refresh_dashboard()

    # ---------- Tabs ----------
    def _build_dashboard_tab(self):
        layout = QVBoxLayout(self.dashboard_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(10)
        title_col = QVBoxLayout()
        title = QLabel("Ransomware Detection")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        subtitle = QLabel("Live monitoring and rapid response")
        subtitle.setStyleSheet("color: #9fb6d0;")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)

        self.status_pill = QLabel("Stopped")
        self.status_pill.setAlignment(Qt.AlignCenter)
        self.status_pill.setFixedWidth(120)
        self.status_pill.setStyleSheet(
            "padding: 8px 12px; border-radius: 16px; background: #2f1f25; color: #f6c7d0;"
        )

        header.addLayout(title_col, stretch=1)
        header.addWidget(self.status_pill, alignment=Qt.AlignRight)
        layout.addLayout(header)

        bar = QHBoxLayout()
        bar.setSpacing(10)

        self.start_btn = QPushButton("Start monitoring")
        self.stop_btn = QPushButton("Stop")
        self.open_logs_btn = QPushButton("Open logs tab")

        for b in (self.start_btn, self.stop_btn, self.open_logs_btn):
            b.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        bar.addWidget(self.start_btn)
        bar.addWidget(self.stop_btn)
        bar.addWidget(self.open_logs_btn)
        bar.addStretch(1)
        layout.addLayout(bar)

        self.status_label = QLabel("Status: Stopped")
        self.status_label.setAlignment(Qt.AlignLeft)
        layout.addWidget(self.status_label)

        stats_group = QGroupBox("Quick stats")
        stats_layout = QGridLayout(stats_group)
        stats_layout.setHorizontalSpacing(18)
        stats_layout.setVerticalSpacing(12)
        stats_group.setStyleSheet(
            "QGroupBox { background: #0b121f; border: 1px solid #233246; border-radius: 12px; padding: 14px 14px 12px 14px; }"
        )
        stats_layout.setColumnStretch(0, 1)
        stats_layout.setColumnStretch(1, 3)

        self.uptime_value = QLabel("—")
        self.logs_value = QLabel("0")
        self.last_event_value = QLabel("—")

        for v in (self.uptime_value, self.logs_value, self.last_event_value):
            v.setFont(QFont("Consolas", 12, QFont.Medium))
            v.setStyleSheet(
                "color: #f4f7ff; background: #111a28; padding: 6px 10px; border-radius: 6px;"
            )
            v.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        def _label(text: str) -> QLabel:
            lbl = QLabel(text)
            lbl.setStyleSheet("color: #9fb6d0; font-weight: 600;")
            return lbl

        stats_layout.addWidget(_label("Uptime:"), 0, 0)
        stats_layout.addWidget(self.uptime_value, 0, 1)

        stats_layout.addWidget(_label("Logs received:"), 1, 0)
        stats_layout.addWidget(self.logs_value, 1, 1)

        stats_layout.addWidget(_label("Last event time:"), 2, 0)
        stats_layout.addWidget(self.last_event_value, 2, 1)

        layout.addWidget(stats_group)

        hint = QLabel(
            "Tip: Keep monitoring running and switch to the Logs tab to inspect events.\n"
            "Use 'Only alerts' or 'Contains' to filter noise."
        )
        hint.setStyleSheet("color: #70809b; padding-top: 8px; line-height: 140%;")
        layout.addWidget(hint)

        layout.addStretch(1)

        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.open_logs_btn.clicked.connect(lambda: self.tabs.setCurrentWidget(self.logs_tab))

    def _build_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        filters_box = QGroupBox("Filters & actions")
        controls = QHBoxLayout(filters_box)
        controls.setSpacing(10)

        self.clear_btn = QPushButton("Clear")
        self.copy_btn = QPushButton("Copy all")
        self.only_alerts_chk = QCheckBox("Only alerts")
        self.contains_edit = QLineEdit()
        self.contains_edit.setPlaceholderText("Contains… (press Enter)")
        self.pause_view_chk = QCheckBox("Pause view")

        for b in (self.clear_btn, self.copy_btn):
            b.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        controls.addWidget(self.clear_btn)
        controls.addWidget(self.copy_btn)
        controls.addSpacing(10)
        controls.addWidget(self.only_alerts_chk)
        controls.addWidget(QLabel("Filter:"))
        controls.addWidget(self.contains_edit, stretch=1)
        controls.addWidget(self.pause_view_chk)

        layout.addWidget(filters_box)

        info = QLabel("Live event feed (alerts highlighted, newest at bottom)")
        info.setStyleSheet("color: #9fb6d0;")
        layout.addWidget(info)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.log_view.setFont(QFont("Consolas", 10))
        self.log_view.setStyleSheet(
            "QPlainTextEdit { background: #0b0f14; color: #8cff8c; border: 1px solid #2a2f3a; }"
        )
        layout.addWidget(self.log_view, stretch=1)
        self.highlighter = LogHighlighter(self.log_view.document())

        self.clear_btn.clicked.connect(self.clear_logs)
        self.copy_btn.clicked.connect(self.copy_all_logs)
        self.contains_edit.returnPressed.connect(self.apply_filters)
        self.only_alerts_chk.stateChanged.connect(self.apply_filters)

    def _build_performance_tab(self):
        """Build unified performance monitoring tab with dark theme"""
        layout = QVBoxLayout(self.performance_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        title_col = QVBoxLayout()
        title = QLabel("⚡ Performance Monitor")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        subtitle = QLabel("Real-time system metrics and process monitoring")
        subtitle.setStyleSheet("color: #9fb6d0;")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header.addLayout(title_col, stretch=1)

        status_col = QVBoxLayout()
        status_label = QLabel("🟡 Monitoring idle")
        status_label.setStyleSheet("color: #f1c40f; font-weight: 600;")
        last_update = QLabel("Last update: --")
        last_update.setStyleSheet("color: #9fb6d0;")
        status_col.addWidget(status_label)
        status_col.addWidget(last_update)
        header.addLayout(status_col)
        layout.addLayout(header)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background-color: #121c2b; }")

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(12)
        content_layout.setContentsMargins(8, 8, 8, 8)

        # System Overview Group
        overview_group = QGroupBox("🔍 SYSTEM OVERVIEW")
        overview_group.setStyleSheet("""
            QGroupBox {
                background-color: #0b121f;
                border: 1px solid #233246;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 15px;
                font-weight: 600;
                color: #9fb6d0;
            }
        """)
        overview_form = QFormLayout(overview_group)
        overview_form.setSpacing(10)
        overview_form.setContentsMargins(12, 12, 12, 12)

        # CPU Bar
        cpu_label = QLabel("CPU Usage:")
        cpu_label.setStyleSheet("color: #d9e5f4; font-weight: 600;")
        cpu_bar = QProgressBar()
        cpu_bar.setMaximum(100)
        cpu_bar.setValue(0)
        cpu_bar.setMinimumHeight(25)
        cpu_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #27364d;
                border-radius: 4px;
                background-color: #0f1724;
                text-align: center;
                color: #27ae60;
                font-weight: 600;
            }
            QProgressBar::chunk { background-color: #27ae60; border-radius: 3px; }
        """)
        cpu_text = QLabel("0%")
        cpu_text.setFont(QFont("Consolas", 11, QFont.Bold))
        cpu_text.setStyleSheet("color: #27ae60; min-width: 50px;")
        cpu_row = QHBoxLayout()
        cpu_row.addWidget(cpu_bar, 1)
        cpu_row.addWidget(cpu_text)
        overview_form.addRow(cpu_label, cpu_row)

        # Memory Bar
        mem_label = QLabel("Memory Usage:")
        mem_label.setStyleSheet("color: #d9e5f4; font-weight: 600;")
        mem_bar = QProgressBar()
        mem_bar.setMaximum(100)
        mem_bar.setValue(0)
        mem_bar.setMinimumHeight(25)
        mem_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #27364d;
                border-radius: 4px;
                background-color: #0f1724;
                text-align: center;
                color: #f1c40f;
                font-weight: 600;
            }
            QProgressBar::chunk { background-color: #f1c40f; border-radius: 3px; }
        """)
        mem_text = QLabel("0%")
        mem_text.setFont(QFont("Consolas", 11, QFont.Bold))
        mem_text.setStyleSheet("color: #f1c40f; min-width: 60px;")
        mem_row = QHBoxLayout()
        mem_row.addWidget(mem_bar, 1)
        mem_row.addWidget(mem_text)
        overview_form.addRow(mem_label, mem_row)

        # Disk Bar
        disk_label = QLabel("Disk Usage:")
        disk_label.setStyleSheet("color: #d9e5f4; font-weight: 600;")
        disk_bar = QProgressBar()
        disk_bar.setMaximum(100)
        disk_bar.setValue(0)
        disk_bar.setMinimumHeight(25)
        disk_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #27364d;
                border-radius: 4px;
                background-color: #0f1724;
                text-align: center;
                color: #e74c3c;
                font-weight: 600;
            }
            QProgressBar::chunk { background-color: #e74c3c; border-radius: 3px; }
        """)
        disk_text = QLabel("0%")
        disk_text.setFont(QFont("Consolas", 11, QFont.Bold))
        disk_text.setStyleSheet("color: #e74c3c; min-width: 60px;")
        disk_row = QHBoxLayout()
        disk_row.addWidget(disk_bar, 1)
        disk_row.addWidget(disk_text)
        overview_form.addRow(disk_label, disk_row)

        content_layout.addWidget(overview_group)

        # Details Row (CPU + Memory)
        details_row = QHBoxLayout()
        details_row.setSpacing(10)

        # CPU Details
        cpu_group = QGroupBox("⚙️ CPU DETAILS")
        cpu_group.setStyleSheet(overview_group.styleSheet())
        cpu_form = QFormLayout(cpu_group)
        cpu_form.setSpacing(8)
        cpu_form.setContentsMargins(12, 12, 12, 12)

        def detail_label(text):
            lbl = QLabel(text)
            lbl.setFont(QFont("Consolas", 10))
            lbl.setStyleSheet("color: #9fb6d0; padding: 4px 8px; background: #0f1724; border-radius: 4px;")
            return lbl

        cpu_cores = detail_label("0 cores")
        cpu_freq = detail_label("0.00 GHz")
        cpu_temp = detail_label("N/A")
        
        cpu_form.addRow(QLabel("Cores:"), cpu_cores)
        cpu_form.addRow(QLabel("Frequency:"), cpu_freq)
        cpu_form.addRow(QLabel("Temperature:"), cpu_temp)
        details_row.addWidget(cpu_group)

        # Memory Details
        mem_group = QGroupBox("🧠 MEMORY DETAILS")
        mem_group.setStyleSheet(overview_group.styleSheet())
        mem_form = QFormLayout(mem_group)
        mem_form.setSpacing(8)
        mem_form.setContentsMargins(12, 12, 12, 12)

        mem_total = detail_label("0 GB")
        mem_used = detail_label("0 GB")
        mem_available = detail_label("0 GB")
        
        mem_form.addRow(QLabel("Total:"), mem_total)
        mem_form.addRow(QLabel("Used:"), mem_used)
        mem_form.addRow(QLabel("Available:"), mem_available)
        details_row.addWidget(mem_group)

        content_layout.addLayout(details_row)

        # Disk Details
        disk_group = QGroupBox("💾 DISK DETAILS")
        disk_group.setStyleSheet(overview_group.styleSheet())
        disk_form = QFormLayout(disk_group)
        disk_form.setSpacing(8)
        disk_form.setContentsMargins(12, 12, 12, 12)

        disk_total = detail_label("0 GB")
        disk_used = detail_label("0 GB")
        disk_free = detail_label("0 GB")
        
        disk_form.addRow(QLabel("Total:"), disk_total)
        disk_form.addRow(QLabel("Used:"), disk_used)
        disk_form.addRow(QLabel("Free:"), disk_free)
        content_layout.addWidget(disk_group)

        # Process Tables
        proc_group = QGroupBox("⚡ TOP PROCESSES")
        proc_group.setStyleSheet(overview_group.styleSheet())
        proc_layout = QVBoxLayout(proc_group)
        proc_layout.setContentsMargins(12, 12, 12, 12)

        table_cpu = QTableWidget()
        table_cpu.setColumnCount(4)
        table_cpu.setHorizontalHeaderLabels(["Process", "PID", "CPU %", "Memory %"])
        table_cpu.setAlternatingRowColors(True)
        table_cpu.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table_cpu.setSelectionMode(QAbstractItemView.NoSelection)
        table_cpu.setMinimumHeight(250)
        table_cpu.setStyleSheet("""
            QTableWidget {
                background-color: #0f1724;
                border: 1px solid #27364d;
                border-radius: 4px;
                gridline-color: #1f2a3a;
                color: #d9e5f4;
            }
            QTableWidget::item { padding: 6px; }
            QTableWidget::item:alternate { background-color: #121c2b; }
            QHeaderView::section {
                background-color: #1f2a3a;
                color: #9fb6d0;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)
        proc_layout.addWidget(QLabel("Top CPU Processes:"))
        proc_layout.addWidget(table_cpu)

        table_mem = QTableWidget()
        table_mem.setColumnCount(4)
        table_mem.setHorizontalHeaderLabels(["Process", "PID", "Memory %", "CPU %"])
        table_mem.setAlternatingRowColors(True)
        table_mem.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table_mem.setSelectionMode(QAbstractItemView.NoSelection)
        table_mem.setMinimumHeight(250)
        table_mem.setStyleSheet(table_cpu.styleSheet())
        proc_layout.addWidget(QLabel("Top Memory Processes:"))
        proc_layout.addWidget(table_mem)

        content_layout.addWidget(proc_group)
        content_layout.addStretch()

        scroll.setWidget(content)
        layout.addWidget(scroll)

        # Store references
        self.perf_labels.update({
            'status': status_label, 'last_update': last_update,
            'cpu_bar': cpu_bar, 'cpu_text': cpu_text,
            'mem_bar': mem_bar, 'mem_text': mem_text,
            'disk_bar': disk_bar, 'disk_text': disk_text,
            'cpu_cores': cpu_cores, 'cpu_freq': cpu_freq, 'cpu_temp': cpu_temp,
            'mem_total': mem_total, 'mem_used': mem_used, 'mem_available': mem_available,
            'disk_total': disk_total, 'disk_used': disk_used, 'disk_free': disk_free,
            'table_cpu': table_cpu, 'table_mem': table_mem
        })

    def _update_perf_callback(self, **kwargs):
        """Thread-safe performance data update callback"""
        if hasattr(self, 'perf_bridge'):
            self.perf_bridge.perf_signal.emit(kwargs)

    def _update_perf_ui(self, data):
        """Update performance UI elements"""
        try:
            # Status
            self.perf_labels['status'].setText("🟢 Monitoring active")
            self.perf_labels['status'].setStyleSheet("color: #27ae60; font-weight: 600;")
            self.perf_labels['last_update'].setText(
                f"Last update: {datetime.now().strftime('%H:%M:%S')}"
            )

            # CPU
            cpu_pct = data.get('cpu_pct', 0)
            self.perf_labels['cpu_bar'].setValue(cpu_pct)
            self.perf_labels['cpu_text'].setText(f"{cpu_pct}%")
            cpu_details = data.get('cpu_details', {})
            self.perf_labels['cpu_cores'].setText(cpu_details.get('cores', '0 cores'))
            self.perf_labels['cpu_freq'].setText(cpu_details.get('freq', 'N/A'))

            # Memory
            mem_pct = data.get('mem_pct', 0)
            self.perf_labels['mem_bar'].setValue(mem_pct)
            self.perf_labels['mem_text'].setText(f"{mem_pct}%")
            mem_details = data.get('mem_details', {})
            self.perf_labels['mem_total'].setText(mem_details.get('total', '0 GB'))
            self.perf_labels['mem_used'].setText(mem_details.get('used', '0 GB'))
            self.perf_labels['mem_available'].setText(mem_details.get('available', '0 GB'))

            # Disk
            disk_pct = data.get('disk_pct', 0)
            self.perf_labels['disk_bar'].setValue(disk_pct)
            self.perf_labels['disk_text'].setText(f"{disk_pct}%")
            disk_details = data.get('disk_details', {})
            self.perf_labels['disk_total'].setText(disk_details.get('total', '0 GB'))
            self.perf_labels['disk_used'].setText(disk_details.get('used', '0 GB'))
            self.perf_labels['disk_free'].setText(disk_details.get('free', '0 GB'))

            # Top Processes
            table = self.perf_labels['table_cpu']
            table.setRowCount(0)
            for proc in data.get('top_cpu_processes', [])[:10]:
                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(proc['name']))
                table.setItem(row, 1, QTableWidgetItem(str(proc['pid'])))
                table.setItem(row, 2, QTableWidgetItem(f"{proc['cpu']:.1f}%"))
                table.setItem(row, 3, QTableWidgetItem(f"{proc['mem']:.1f}%"))

            table_mem = self.perf_labels['table_mem']
            table_mem.setRowCount(0)
            for proc in data.get('top_mem_processes', [])[:10]:
                row = table_mem.rowCount()
                table_mem.insertRow(row)
                table_mem.setItem(row, 0, QTableWidgetItem(proc['name']))
                table_mem.setItem(row, 1, QTableWidgetItem(str(proc['pid'])))
                table_mem.setItem(row, 2, QTableWidgetItem(f"{proc['mem']:.1f}%"))
                table_mem.setItem(row, 3, QTableWidgetItem(f"{proc['cpu']:.1f}%"))
        except Exception as e:
            pass

    # ---------- Helpers ----------
    def _apply_theme(self):
        self.setStyleSheet(
            """
            QWidget { background-color: #0f1724; color: #e4edf7; font-family: 'Segoe UI'; }
            QTabWidget::pane { border: 1px solid #1f2a3a; border-radius: 10px; background: #121c2b; }
            QTabBar::tab { background: #121c2b; color: #9fb6d0; padding: 8px 14px; border: 1px solid #1f2a3a; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 4px; }
            QTabBar::tab:selected { background: #1e2a3d; color: #f3f8ff; }
            QGroupBox { border: 1px solid #1f2a3a; border-radius: 10px; margin-top: 12px; padding: 10px 12px 12px 12px; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; color: #9fb6d0; }
            QLabel { color: #d9e5f4; }
            QPushButton { background: #1f2a3a; color: #e4edf7; border: 1px solid #30415a; border-radius: 6px; padding: 8px 14px; }
            QPushButton:hover { background: #26344a; }
            QPushButton:disabled { background: #192233; color: #6f7d94; }
            QLineEdit { background: #0f1724; border: 1px solid #27364d; border-radius: 6px; padding: 6px 8px; color: #e4edf7; }
            QCheckBox { color: #d9e5f4; spacing: 8px; }
            QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #3c4b63; background: #0f1724; }
            QCheckBox::indicator:hover { border: 1px solid #4f6687; }
            QCheckBox::indicator:checked { background: #1d7f5d; border: 1px solid #2cb586; }
            QPlainTextEdit { border-radius: 10px; }
            """
        )

        # All primary actions styled red (action = red)
        action_btn_style = (
            "background: #7a2435; border: 1px solid #a33043; color: #ffd5de; padding: 10px 16px;"
        )
        self.start_btn.setStyleSheet(action_btn_style)
        self.stop_btn.setStyleSheet(action_btn_style)
        self.open_logs_btn.setStyleSheet(action_btn_style)

        self.log_view.setStyleSheet(
            "QPlainTextEdit { background: #0b111a; color: #d3f0d3; border: 1px solid #2a3547; border-radius: 10px; }")

    def set_status(self, monitoring: bool):
        if monitoring:
            self.status_label.setText("Status: Monitoring")
        else:
            self.status_label.setText("Status: Stopped")

        # Status = yellow (consistent for any state)
        self.status_label.setStyleSheet("color: #f1c40f; font-weight: 600;")
        self.status_pill.setText("Monitoring" if monitoring else "Stopped")
        self.status_pill.setStyleSheet(
            "padding: 8px 12px; border-radius: 16px; background: #4c3f00; color: #ffe680;"
        )

    def update_controls(self):
        self.start_btn.setEnabled(not self.monitoring)
        self.stop_btn.setEnabled(self.monitoring)

    def refresh_dashboard(self):
        self.set_status(self.monitoring)
        self.logs_value.setText(str(self.total_logs))

        if self.monitoring and self.started_at:
            delta = datetime.now() - self.started_at
            total_s = int(delta.total_seconds())
            h = total_s // 3600
            m = (total_s % 3600) // 60
            s = total_s % 60
            self.uptime_value.setText(f"{h:02d}:{m:02d}:{s:02d}")
        else:
            self.uptime_value.setText("—")

    # ---------- Logging ----------
    def on_log_line(self, msg: str):
        self.total_logs += 1
        self.log_history.append(msg)
        self.last_event_value.setText(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        if self.pause_view_chk.isChecked():
            return

        if not self._passes_filters(msg):
            return

        self.log_view.appendPlainText(msg)
        cursor = self.log_view.textCursor()
        cursor.movePosition(cursor.End)
        self.log_view.setTextCursor(cursor)

    def _passes_filters(self, msg: str) -> bool:
        if self.only_alerts_chk.isChecked():
            keywords = ("alert", "warning", "danger", "blocked", "ransom", "malware", "suspicious")
            if not any(k in msg.lower() for k in keywords):
                return False

        text = self.contains_edit.text().strip()
        if text and (text.lower() not in msg.lower()):
            return False

        return True

    def apply_filters(self):
        self.log_view.clear()
        for line in self.log_history:
            if self._passes_filters(line):
                self.log_view.appendPlainText(line)

        cursor = self.log_view.textCursor()
        cursor.movePosition(cursor.End)
        self.log_view.setTextCursor(cursor)

    def clear_logs(self):
        self.log_view.clear()
        self.total_logs = 0
        self.log_history.clear()
        self.last_event_value.setText("—")
        self.refresh_dashboard()

    def copy_all_logs(self):
        QApplication.clipboard().setText(self.log_view.toPlainText())

    # ---------- Engine controls ----------
    def start_monitoring(self):
        if self.monitoring:
            return

        self.monitoring = True
        self.started_at = datetime.now()
        self.refresh_dashboard()
        self.update_controls()

        threading.Thread(target=self.engine.start, daemon=True).start()

    def stop_monitoring(self):
        if not self.monitoring:
            return

        try:
            self.engine.stop()
        finally:
            self.monitoring = False
            self.started_at = None
            self.refresh_dashboard()
            self.update_controls()

    def closeEvent(self, event):
        if self.monitoring:
            reply = QMessageBox.question(
                self,
                "Exit",
                "Monitoring is running. Stop and exit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                event.ignore()
                return

            self.stop_monitoring()
        
        # Stop performance monitoring
        if hasattr(self, 'perf_monitor'):
            self.perf_monitor.stop()

        event.accept()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
