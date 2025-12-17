"""Scanner tab - On-demand scanning interface"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QProgressBar,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QRadioButton,
    QButtonGroup, QGroupBox, QHeaderView, QMessageBox, QFrame, QTabWidget, QCheckBox,
    QTextEdit, QDialog, QScrollArea
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor

from workers.scanner_worker_advanced import AdvancedScannerWorker
from core.quarantine_manager import QuarantineManager
from core.process_terminator import ProcessTerminator
from gui.styles import (
    COLOR_PRIMARY, COLOR_SUCCESS, COLOR_CRITICAL, COLOR_WARNING,
    COLOR_BG_LIGHT, FONT_FAMILY, FONT_SIZE_TITLE, FONT_SIZE_SUBTITLE, FONT_SIZE_BODY
)
import os
import subprocess
import psutil


class ScannerPage(QWidget):
    """On-demand scanner page."""
    
    def __init__(self, config, logger, parent=None):
        super().__init__(parent)
        self.config = config
        self.logger = logger
        self.worker = None
        
        # Initialize quarantine manager
        quarantine_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'quarantine')
        self.quarantine_manager = QuarantineManager(quarantine_dir, logger)
        
        # Initialize process terminator
        self.process_terminator = ProcessTerminator(logger)
        
        # Store threat data for detail view
        self.threat_data = {}  # row -> event data mapping
        
        self._build_ui()
    
    def _build_ui(self):
        """Build the scanner UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("🔍 On-Demand Scanner")
        title.setFont(QFont(FONT_FAMILY, FONT_SIZE_TITLE, QFont.Bold))
        title.setStyleSheet(f"color: {COLOR_PRIMARY};")
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Scan your system for ransomware threats")
        subtitle.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        subtitle.setStyleSheet("color: #666;")
        layout.addWidget(subtitle)
        
        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background-color: #ddd; height: 2px;")
        layout.addWidget(sep)
        
        # Create sub tabs inside Scanner page
        self.subtabs = QTabWidget()
        self.subtabs.setTabPosition(QTabWidget.North)
        self.subtabs.setMovable(False)
        self.subtabs.setDocumentMode(True)

        # ===== Scanner tab (controls) =====
        tab_scanner = QWidget()
        scanner_tab_layout = QVBoxLayout(tab_scanner)
        scanner_tab_layout.setSpacing(12)

        # Top row: Scan mode + Targets
        top_layout = QHBoxLayout()
        
        # Scan Mode
        mode_group = QGroupBox("Scan Mode")
        mode_group.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        mode_layout = QVBoxLayout(mode_group)
        
        self.fast_radio = QRadioButton("⚡ Fast Scan (Documents, Desktop, Downloads)")
        self.fast_radio.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.fast_radio.setChecked(True)
        
        self.full_radio = QRadioButton("🔬 Full Scan (Entire system)")
        self.full_radio.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        
        self.btn_group = QButtonGroup()
        self.btn_group.addButton(self.fast_radio)
        self.btn_group.addButton(self.full_radio)
        
        mode_layout.addWidget(self.fast_radio)
        mode_layout.addWidget(self.full_radio)
        mode_layout.addStretch()
        
        top_layout.addWidget(mode_group, 1)
        
        # Scan Targets
        targets_group = QGroupBox("Scan Targets")
        targets_group.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        targets_layout = QVBoxLayout(targets_group)
        
        self.targets_tree = QTreeWidget()
        self.targets_tree.setHeaderLabel("Select targets to scan")
        self.targets_tree.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.targets_tree.itemChanged.connect(self._on_item_changed)
        
        # Add default targets
        self._populate_targets()
        
        targets_layout.addWidget(self.targets_tree)
        
        top_layout.addWidget(targets_group, 2)
        
        scanner_tab_layout.addLayout(top_layout)
        
        # Scan button and progress
        scan_layout = QVBoxLayout()
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_scan = QPushButton("▶️  Start Scan")
        self.btn_scan.setMinimumHeight(50)
        self.btn_scan.setMinimumWidth(200)
        self.btn_scan.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        self.btn_scan.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_SUCCESS};
                color: white;
                padding: 14px 28px;
                border-radius: 8px;
                border: none;
                font-size: 14pt;
            }}
            QPushButton:hover {{
                background-color: #27AE60;
            }}
            QPushButton:pressed {{
                background-color: #1E8449;
            }}
            QPushButton:disabled {{
                background-color: #95a5a6;
            }}
        """)
        self.btn_scan.clicked.connect(self.start_scan)
        
        self.btn_stop = QPushButton("⏹️  Stop Scan")
        self.btn_stop.setMinimumHeight(50)
        self.btn_stop.setMinimumWidth(150)
        self.btn_stop.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY, QFont.Bold))
        self.btn_stop.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CRITICAL};
                color: white;
                padding: 14px 28px;
                border-radius: 8px;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #C0392B;
            }}
            QPushButton:disabled {{
                background-color: #95a5a6;
            }}
        """)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_stop.setEnabled(False)
        
        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addStretch()
        
        scan_layout.addLayout(btn_layout)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setMaximum(100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid #ddd;
                border-radius: 8px;
                text-align: center;
                height: 30px;
                background-color: white;
            }}
            QProgressBar::chunk {{
                background-color: {COLOR_SUCCESS};
                border-radius: 6px;
            }}
        """)
        
        scan_layout.addWidget(self.progress)
        
        # Status label
        self.lbl_status = QLabel("Ready to scan")
        self.lbl_status.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.lbl_status.setStyleSheet("color: #666; padding: 8px;")
        self.lbl_status.setAlignment(Qt.AlignCenter)
        
        scan_layout.addWidget(self.lbl_status)
        
        scanner_tab_layout.addLayout(scan_layout)

        self.subtabs.addTab(tab_scanner, "Scanner")

        # ===== Reports tab (summary + live counters) =====
        tab_reports = QWidget()
        reports_layout = QVBoxLayout(tab_reports)
        reports_layout.setSpacing(12)
        reports_layout.setContentsMargins(12, 12, 12, 12)

        # Scanning Process panel
        process_box = QGroupBox("Scanning Process")
        process_box.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        process_layout = QVBoxLayout(process_box)

        self.reports_folder_label = QLabel("Folder :")
        self.reports_folder_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.reports_folder_label.setStyleSheet("color: #2c3e50;")
        process_layout.addWidget(self.reports_folder_label)

        self.reports_progress_bar = QProgressBar()
        self.reports_progress_bar.setMinimum(0)
        self.reports_progress_bar.setMaximum(100)
        self.reports_progress_bar.setValue(0)
        self.reports_progress_bar.setTextVisible(True)
        self.reports_progress_bar.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.reports_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #ddd;
                border-radius: 8px;
                text-align: center;
                height: 24px;
                background-color: white;
            }
            QProgressBar::chunk {
                background-color: #2ecc71;
                border-radius: 6px;
            }
        """)
        process_layout.addWidget(self.reports_progress_bar)

        self.reports_info_label = QLabel("Info :")
        self.reports_info_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.reports_info_label.setStyleSheet("color: #2c3e50;")
        process_layout.addWidget(self.reports_info_label)

        reports_layout.addWidget(process_box)

        # Scanning Result panel
        results_box = QGroupBox("Scanning Result")
        results_box.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        box_layout = QVBoxLayout(results_box)
        self.lbl_reports_summary = QLabel("0 Data checked/scanned\n0 Threats Detected\n0 Registry Error/Hidden Files")
        self.lbl_reports_summary.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.lbl_reports_summary.setStyleSheet("color: #2c3e50;")
        box_layout.addWidget(self.lbl_reports_summary)
        reports_layout.addWidget(results_box)

        # Action buttons row
        actions_layout = QHBoxLayout()
        actions_layout.setSpacing(18)
        actions_layout.addStretch()

        # Common style for dark green buttons
        dark_btn_style = (
            "QPushButton {"
            " background-color: #0B5E21;"
            " color: white;"
            " font-weight: bold;"
            " padding: 10px 18px;"
            " border-radius: 8px;"
            " border: none;"
            "}"
            " QPushButton:hover { background-color: #0F7A2A; }"
            " QPushButton:pressed { background-color: #095419; }"
            " QPushButton:disabled { background-color: #95a5a6; }"
        )

        self.btn_fix_all = QPushButton("Fix All")
        self.btn_fix_all.setMinimumHeight(44)
        self.btn_fix_all.setMinimumWidth(160)
        self.btn_fix_all.setStyleSheet(dark_btn_style)
        self.btn_fix_all.clicked.connect(self._on_fix_all)
        actions_layout.addWidget(self.btn_fix_all)

        # Right column with Mini-Form and Log stacked
        right_col = QVBoxLayout()
        right_col.setSpacing(8)
        self.btn_mini_form = QPushButton("Mini-Form")
        self.btn_mini_form.setMinimumHeight(32)
        self.btn_mini_form.setMinimumWidth(120)
        self.btn_mini_form.setStyleSheet(dark_btn_style)
        self.btn_mini_form.clicked.connect(self._on_mini_form)
        right_col.addWidget(self.btn_mini_form)

        self.btn_log = QPushButton("Log")
        self.btn_log.setMinimumHeight(32)
        self.btn_log.setMinimumWidth(120)
        self.btn_log.setStyleSheet(dark_btn_style)
        self.btn_log.clicked.connect(self._on_open_log)
        right_col.addWidget(self.btn_log)

        actions_layout.addLayout(right_col)

        self.btn_stop_result = QPushButton("Stop")
        self.btn_stop_result.setMinimumHeight(44)
        self.btn_stop_result.setMinimumWidth(180)
        self.btn_stop_result.setStyleSheet(dark_btn_style)
        self.btn_stop_result.clicked.connect(self._on_stop_or_result)
        actions_layout.addWidget(self.btn_stop_result)

        reports_layout.addLayout(actions_layout)

        self.subtabs.addTab(tab_reports, "Reports")

        # ===== Ransomware tab (results table) =====
        tab_ransom = QWidget()
        ransom_layout = QVBoxLayout(tab_ransom)
        ransom_layout.setSpacing(12)
        ransom_layout.setContentsMargins(12, 12, 12, 12)
        ransom_group = QGroupBox("Ransomware Findings")
        ransom_group.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        rgroup_layout = QVBoxLayout(ransom_group)
        rgroup_layout.addWidget(self._build_results_table())
        ransom_layout.addWidget(ransom_group)
        self.subtabs.addTab(tab_ransom, "Ransomware")

        # ===== Registry tab =====
        tab_registry = QWidget()
        registry_layout = QVBoxLayout(tab_registry)
        registry_layout.setSpacing(12)
        registry_layout.setContentsMargins(12, 12, 12, 12)
        registry_group = QGroupBox("Registry Autorun Findings")
        registry_group.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        reg_group_layout = QVBoxLayout(registry_group)
        
        self.registry_table = QTableWidget()
        self.registry_table.setColumnCount(5)
        self.registry_table.setHorizontalHeaderLabels(['☑', 'Name', 'Type', 'File Path', 'Status'])
        self.registry_table.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.registry_table.horizontalHeader().setStretchLastSection(True)
        self.registry_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.registry_table.setColumnWidth(0, 40)
        self.registry_table.setAlternatingRowColors(True)
        self.registry_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.registry_table.setStyleSheet("""
            QTableWidget {
                background-color: white;
                gridline-color: #ddd;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: black;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)
        reg_group_layout.addWidget(self.registry_table)
        
        reg_actions = QHBoxLayout()
        self.chk_select_all_reg = QCheckBox("Select All")
        self.chk_select_all_reg.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.chk_select_all_reg.stateChanged.connect(lambda state: self._toggle_all_checks(self.registry_table, state))
        reg_actions.addWidget(self.chk_select_all_reg)
        reg_actions.addStretch()
        
        btn_clean_all_reg = QPushButton("Clean All")
        btn_clean_all_reg.setMinimumHeight(36)
        btn_clean_all_reg.setStyleSheet(self._action_button_style())
        btn_clean_all_reg.clicked.connect(lambda: self._clean_all(self.registry_table))
        reg_actions.addWidget(btn_clean_all_reg)
        
        btn_clean_checked_reg = QPushButton("Clean Checked")
        btn_clean_checked_reg.setMinimumHeight(36)
        btn_clean_checked_reg.setStyleSheet(self._action_button_style())
        btn_clean_checked_reg.clicked.connect(lambda: self._clean_checked(self.registry_table))
        reg_actions.addWidget(btn_clean_checked_reg)
        
        btn_more_reg = QPushButton("More >>")
        btn_more_reg.setMinimumHeight(36)
        btn_more_reg.setStyleSheet(self._action_button_style())
        btn_more_reg.clicked.connect(self._show_more_options)
        reg_actions.addWidget(btn_more_reg)
        
        btn_explore_reg = QPushButton("Explore")
        btn_explore_reg.setMinimumHeight(36)
        btn_explore_reg.setStyleSheet(self._action_button_style())
        btn_explore_reg.clicked.connect(lambda: self._explore_selected(self.registry_table))
        reg_actions.addWidget(btn_explore_reg)
        
        btn_properties_reg = QPushButton("Properties")
        btn_properties_reg.setMinimumHeight(36)
        btn_properties_reg.setStyleSheet(self._action_button_style())
        btn_properties_reg.clicked.connect(lambda: self._show_properties(self.registry_table))
        reg_actions.addWidget(btn_properties_reg)
        
        reg_group_layout.addLayout(reg_actions)
        registry_layout.addWidget(registry_group)
        self.subtabs.addTab(tab_registry, "Registry")

        # ===== Hidden tab =====
        tab_hidden = QWidget()
        hidden_layout = QVBoxLayout(tab_hidden)
        hidden_layout.setSpacing(12)
        hidden_layout.setContentsMargins(12, 12, 12, 12)
        hidden_group = QGroupBox("Hidden Files Findings")
        hidden_group.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        hid_group_layout = QVBoxLayout(hidden_group)
        
        self.hidden_table = QTableWidget()
        self.hidden_table.setColumnCount(5)
        self.hidden_table.setHorizontalHeaderLabels(['☑', 'Name', 'Type', 'File Path', 'Status'])
        self.hidden_table.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.hidden_table.horizontalHeader().setStretchLastSection(True)
        self.hidden_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.hidden_table.setColumnWidth(0, 40)
        self.hidden_table.setAlternatingRowColors(True)
        self.hidden_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hidden_table.setStyleSheet("""
            QTableWidget {
                background-color: white;
                gridline-color: #ddd;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: black;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)
        hid_group_layout.addWidget(self.hidden_table)
        
        hid_actions = QHBoxLayout()
        self.chk_select_all_hid = QCheckBox("Select All")
        self.chk_select_all_hid.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.chk_select_all_hid.stateChanged.connect(lambda state: self._toggle_all_checks(self.hidden_table, state))
        hid_actions.addWidget(self.chk_select_all_hid)
        hid_actions.addStretch()
        
        btn_clean_all_hid = QPushButton("Clean All")
        btn_clean_all_hid.setMinimumHeight(36)
        btn_clean_all_hid.setStyleSheet(self._action_button_style())
        btn_clean_all_hid.clicked.connect(lambda: self._clean_all(self.hidden_table))
        hid_actions.addWidget(btn_clean_all_hid)
        
        btn_clean_checked_hid = QPushButton("Clean Checked")
        btn_clean_checked_hid.setMinimumHeight(36)
        btn_clean_checked_hid.setStyleSheet(self._action_button_style())
        btn_clean_checked_hid.clicked.connect(lambda: self._clean_checked(self.hidden_table))
        hid_actions.addWidget(btn_clean_checked_hid)
        
        btn_more_hid = QPushButton("More >>")
        btn_more_hid.setMinimumHeight(36)
        btn_more_hid.setStyleSheet(self._action_button_style())
        btn_more_hid.clicked.connect(self._show_more_options)
        hid_actions.addWidget(btn_more_hid)
        
        btn_explore_hid = QPushButton("Explore")
        btn_explore_hid.setMinimumHeight(36)
        btn_explore_hid.setStyleSheet(self._action_button_style())
        btn_explore_hid.clicked.connect(lambda: self._explore_selected(self.hidden_table))
        hid_actions.addWidget(btn_explore_hid)
        
        btn_properties_hid = QPushButton("Properties")
        btn_properties_hid.setMinimumHeight(36)
        btn_properties_hid.setStyleSheet(self._action_button_style())
        btn_properties_hid.clicked.connect(lambda: self._show_properties(self.hidden_table))
        hid_actions.addWidget(btn_properties_hid)
        
        hid_group_layout.addLayout(hid_actions)
        hidden_layout.addWidget(hidden_group)
        self.subtabs.addTab(tab_hidden, "Hidden")

        # Add subtabs to main layout
        layout.addWidget(self.subtabs)

        # Initialize Reports buttons visibility for idle state
        self._report_mode_running = False
        # Hide Stop/Result until a scan starts or completes
        self.btn_stop_result.setVisible(False)
        
    def _build_results_table(self):
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels([
            '☑', 'Severity', 'Type', 'Path', 'Reason', 'Score', 'Timestamp'
        ])
        table.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        table.setColumnWidth(0, 40)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setStyleSheet("""
            QTableWidget {
                background-color: white;
                gridline-color: #ddd;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: black;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)
        self.results_table = table
        # Summary label under table inside Ransomware tab
        self.lbl_summary = QLabel("Threats found: 0 | Items scanned: 0")
        self.lbl_summary.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY, QFont.Bold))
        self.lbl_summary.setStyleSheet(f"color: {COLOR_PRIMARY}; padding: 8px;")
        
        # Select All checkbox and action buttons
        select_layout = QHBoxLayout()
        self.chk_select_all_ransom = QCheckBox("Select All")
        self.chk_select_all_ransom.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        self.chk_select_all_ransom.stateChanged.connect(lambda state: self._toggle_all_checks(table, state))
        select_layout.addWidget(self.chk_select_all_ransom)
        select_layout.addStretch()
        
        btn_clean_all = QPushButton("Clean All")
        btn_clean_all.setMinimumHeight(36)
        btn_clean_all.setStyleSheet(self._action_button_style())
        btn_clean_all.clicked.connect(lambda: self._clean_all(table))
        select_layout.addWidget(btn_clean_all)
        
        btn_clean_checked = QPushButton("Clean Checked")
        btn_clean_checked.setMinimumHeight(36)
        btn_clean_checked.setStyleSheet(self._action_button_style())
        btn_clean_checked.clicked.connect(lambda: self._clean_checked(table))
        select_layout.addWidget(btn_clean_checked)
        
        btn_more = QPushButton("More >>")
        btn_more.setMinimumHeight(36)
        btn_more.setStyleSheet(self._action_button_style())
        btn_more.clicked.connect(self._show_more_options)
        select_layout.addWidget(btn_more)
        
        btn_explore = QPushButton("Explore")
        btn_explore.setMinimumHeight(36)
        btn_explore.setStyleSheet(self._action_button_style())
        btn_explore.clicked.connect(lambda: self._explore_selected(table))
        select_layout.addWidget(btn_explore)
        
        btn_properties = QPushButton("Properties")
        btn_properties.setMinimumHeight(36)
        btn_properties.setStyleSheet(self._action_button_style())
        btn_properties.clicked.connect(lambda: self._show_properties(table))
        select_layout.addWidget(btn_properties)
        
        container = QWidget()
        v = QVBoxLayout(container)
        v.setContentsMargins(0,0,0,0)
        v.addWidget(table)
        v.addLayout(select_layout)
        v.addWidget(self.lbl_summary)
        return container
    
    def _populate_targets(self):
        """Populate scan targets tree."""
        self.targets_tree.clear()
        
        # Filesystem
        fs_item = QTreeWidgetItem(self.targets_tree, ['💾 Computer Drives'])
        fs_item.setCheckState(0, Qt.Checked)
        fs_item.setData(0, Qt.UserRole, {'type': 'filesystem', 'path': None})
        
        # Add drives (Windows)
        import string
        for drive in string.ascii_uppercase:
            drive_path = f"{drive}:\\"
            if os.path.exists(drive_path):
                drive_item = QTreeWidgetItem(fs_item, [f"{drive}:\\"])
                drive_item.setCheckState(0, Qt.Checked if drive == 'C' else Qt.Unchecked)
                drive_item.setData(0, Qt.UserRole, {'type': 'filesystem', 'path': drive_path})
        
        # Processes
        proc_item = QTreeWidgetItem(self.targets_tree, ['⚙️ Running Processes'])
        proc_item.setCheckState(0, Qt.Checked)
        proc_item.setData(0, Qt.UserRole, {'type': 'process'})
        
        # Registry (Windows only)
        import sys
        if sys.platform == 'win32':
            reg_item = QTreeWidgetItem(self.targets_tree, ['📋 Registry Autorun'])
            reg_item.setCheckState(0, Qt.Checked)
            reg_item.setData(0, Qt.UserRole, {'type': 'registry'})
        
        # Hidden files
        hidden_item = QTreeWidgetItem(self.targets_tree, ['👁️ Hidden Files'])
        hidden_item.setCheckState(0, Qt.Unchecked)
        hidden_item.setData(0, Qt.UserRole, {'type': 'hidden', 'path': 'C:\\'})
        
        self.targets_tree.expandAll()
        # Ensure parent reflects initial children state
        self._update_parent_state(fs_item)
        self._update_parent_state(proc_item)
        if sys.platform == 'win32':
            self._update_parent_state(reg_item)
        self._update_parent_state(hidden_item)

    def _on_item_changed(self, item, column):
        # Prevent recursive signal storms
        self.targets_tree.blockSignals(True)
        try:
            state = item.checkState(0)
            # Propagate to children when a parent toggled
            for i in range(item.childCount()):
                child = item.child(i)
                child.setCheckState(0, state)
            # Update parents (tri-state up the chain)
            self._update_parent_state(item.parent())
        finally:
            self.targets_tree.blockSignals(False)

    def _update_parent_state(self, parent):
        if parent is None:
            return
        total = parent.childCount()
        if total == 0:
            return
        checked = 0
        partial = False
        for i in range(total):
            st = parent.child(i).checkState(0)
            if st == Qt.PartiallyChecked:
                partial = True
            elif st == Qt.Checked:
                checked += 1
        if partial or (0 < checked < total):
            parent.setCheckState(0, Qt.PartiallyChecked)
        elif checked == total:
            parent.setCheckState(0, Qt.Checked)
        else:
            parent.setCheckState(0, Qt.Unchecked)
        # Recurse up
        self._update_parent_state(parent.parent())
    
    def _collect_targets(self):
        """Collect selected scan targets."""
        targets = []
        
        root = self.targets_tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            
            if item.checkState(0) == Qt.Checked:
                data = item.data(0, Qt.UserRole)
                if data:
                    # Check if it's a parent item with children
                    if item.childCount() > 0:
                        # Add checked children
                        for j in range(item.childCount()):
                            child = item.child(j)
                            if child.checkState(0) == Qt.Checked:
                                child_data = child.data(0, Qt.UserRole)
                                if child_data:
                                    targets.append(child_data)
                    else:
                        targets.append(data)
        
        return targets
    
    def start_scan(self):
        """Start the scan."""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Scan Running", "A scan is already in progress.")
            return
        
        # Collect targets
        targets = self._collect_targets()
        
        if not targets:
            QMessageBox.warning(self, "No Targets", "Please select at least one scan target.")
            return
        
        # Get mode
        mode = 'fast' if self.fast_radio.isChecked() else 'full'
        
        # Clear results
        self.results_table.setRowCount(0)
        self.progress.setValue(0)
        self.lbl_status.setText("Starting scan...")
        self.lbl_summary.setText("Threats found: 0 | Items scanned: 0")
        # Reports live counters
        folder_text = ", ".join([t.get('path', t.get('type')) for t in targets if t.get('path')]) or ("Fast Scan" if mode == 'fast' else f"{len(targets)} targets")
        self.reports_folder_label.setText(f"Folder : {folder_text}")
        self.reports_progress_bar.setValue(0)
        self.reports_info_label.setText("Info : Starting scan...")
        self.lbl_reports_summary.setText("0 Data checked/scanned\n0 Threats Detected\n0 Registry Error/Hidden Files")
        
        # Create and start advanced worker
        self.worker = AdvancedScannerWorker(targets, mode, self.config, self.logger)
        self.worker.progress.connect(self._on_progress)
        self.worker.threat_found.connect(self._on_threat_found)
        self.worker.status_update.connect(self._on_status_update)
        self.worker.finished.connect(self._on_scan_complete)
        
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_stop_result.setText("Stop")
        self.btn_stop_result.setVisible(True)
        self._report_mode_running = True
        
        # Switch to Reports tab
        self.subtabs.setCurrentIndex(1)
        self.worker.start()
    
    def stop_scan(self):
        """Stop the scan."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.lbl_status.setText("Stopping scan...")
            self.btn_stop.setEnabled(False)
            self.reports_info_label.setText("Info : Stopping scan...")
    
    def _on_progress(self, percent):
        """Update progress bar."""
        self.progress.setValue(percent)
        self.reports_progress_bar.setValue(percent)
        # Update reports summary first line with items scanned if available
        if self.worker:
            items = getattr(self.worker, 'items_scanned', 0)
            # Preserve other lines
            lines = self.lbl_reports_summary.text().split('\n')
            lines[0] = f"{items} Data checked/scanned"
            self.lbl_reports_summary.setText('\n'.join(lines))
    
    def _on_status_update(self, status):
        """Update status label."""
        self.lbl_status.setText(status)
        self.reports_info_label.setText(f"Info : {status}")
    
    def _on_threat_found(self, event):
        """Add threat to results table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Store full event data for detail view
        self.threat_data[row] = event
        
        # Checkbox in column 0
        chk = QCheckBox()
        chk.setStyleSheet("margin-left: 10px;")
        self.results_table.setCellWidget(row, 0, chk)
        
        # Severity in column 1
        severity = event.get('severity', 'INFO')
        severity_item = QTableWidgetItem(severity)
        severity_item.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY, QFont.Bold))
        
        if severity == 'CRITICAL':
            severity_item.setBackground(QColor(231, 76, 60))
            severity_item.setForeground(QColor(0, 0, 0))
        elif severity == 'WARNING':
            severity_item.setBackground(QColor(243, 156, 18))
            severity_item.setForeground(QColor(0, 0, 0))
        else:
            severity_item.setBackground(QColor(52, 152, 219))
            severity_item.setForeground(QColor(0, 0, 0))
        
        self.results_table.setItem(row, 1, severity_item)
        
        # Type in column 2
        self.results_table.setItem(row, 2, QTableWidgetItem(event.get('type', 'N/A')))
        
        # Path in column 3
        path_item = QTableWidgetItem(event.get('path', 'N/A')[:80])
        path_item.setToolTip(event.get('path', 'N/A'))
        self.results_table.setItem(row, 3, path_item)
        
        # Reason in column 4
        self.results_table.setItem(row, 4, QTableWidgetItem(event.get('reason', 'N/A')))
        
        # Score in column 5
        self.results_table.setItem(row, 5, QTableWidgetItem(str(event.get('score', 0))))
        
        # Timestamp in column 6
        self.results_table.setItem(row, 6, QTableWidgetItem(event.get('timestamp', '')[:19]))
        
        # Connect double-click to show details
        self.results_table.itemDoubleClicked.connect(self._on_row_double_clicked)
        
        # Auto-scroll to bottom
        self.results_table.scrollToBottom()
        
        # Update summary
        threats = self.results_table.rowCount()
        items_val = self.worker.items_scanned if self.worker else 0
        self.lbl_summary.setText(f"⚠️ Threats found: {threats} | Items scanned: {items_val}")
        # Update reports summary second line
        lines = self.lbl_reports_summary.text().split('\n')
        lines[1] = f"{threats} Threats Detected"
        self.lbl_reports_summary.setText('\n'.join(lines))
    
    def _on_scan_complete(self, summary):
        """Handle scan completion."""
        self.progress.setValue(100)
        self.reports_progress_bar.setValue(100)
        
        duration = summary.get('duration', 0)
        items = summary.get('items', 0)
        threats = summary.get('threats', 0)
        clean = summary.get('clean', 0)
        
        status_msg = f"✅ Scan complete! Duration: {duration:.1f}s | Items: {items} | Threats: {threats} | Clean: {clean}"
        self.lbl_status.setText(status_msg)
        
        self.lbl_summary.setText(f"Threats found: {threats} | Items scanned: {items}")
        lines = self.lbl_reports_summary.text().split('\n')
        lines[0] = f"{items} Data checked/scanned"
        lines[1] = f"{threats} Threats Detected"
        lines[2] = f"{summary.get('registry_errors', 0)} Registry Error/Hidden Files"
        self.lbl_reports_summary.setText('\n'.join(lines))
        
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        # Change Stop to Result >> and enable click to go to Ransomware tab
        self.btn_stop_result.setText("Result >>")
        self.btn_stop_result.setVisible(True)
        self._report_mode_running = False
        
        # Show summary dialog
        if threats > 0:
            QMessageBox.warning(
                self,
                "⚠️ Threats Detected",
                f"Scan found {threats} potential threats.\n\n"
                f"Please review the results and take appropriate action.\n\n"
                f"Note: This is a detection-only scan. No files have been modified."
            )
        else:
            QMessageBox.information(
                self,
                "✅ Scan Complete",
                f"No threats detected!\n\n"
                f"Scanned {items} items in {duration:.1f} seconds."
            )

    def _on_stop_or_result(self):
        """Handle Stop during running, or Result >> after completion."""
        if getattr(self, '_report_mode_running', False):
            self.stop_scan()
        else:
            # Switch to Ransomware tab
            # Tabs order: 0 Scanner, 1 Reports, 2 Ransomware
            self.subtabs.setCurrentIndex(2)

    def _on_fix_all(self):
        """Placeholder: show guidance; future: quarantine/delete actions."""
        QMessageBox.information(
            self,
            "Fix All",
            "This action will provide remediation options (quarantine/delete) for detected threats."
        )

        # Future: iterate results and apply actions.

    def _on_mini_form(self):
        """Show a compact summary dialog (mini-form)."""
        text = self.lbl_reports_summary.text().replace('\n', '\n\n')
        QMessageBox.information(self, "Mini-Form", text)

    def _on_open_log(self):
        """Open logs summary or show latest entries."""
        try:
            import os
            logs_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'events.jsonl')
            if os.path.exists(logs_path):
                QMessageBox.information(self, "Log", f"Log file: {logs_path}")
            else:
                QMessageBox.warning(self, "Log", "Log file not found.")
        except Exception as e:
            QMessageBox.warning(self, "Log", f"Unable to open logs: {e}")
    
    def _action_button_style(self):
        """Consistent style for action buttons."""
        return (
            "QPushButton {"
            " background-color: #95a5a6;"
            " color: white;"
            " font-weight: bold;"
            " padding: 8px 16px;"
            " border-radius: 6px;"
            " border: none;"
            "}"
            " QPushButton:hover { background-color: #7f8c8d; }"
            " QPushButton:pressed { background-color: #606b6c; }"
        )

    def _toggle_all_checks(self, table, state):
        """Toggle all checkboxes in a table."""
        checked = (state == 2)  # Qt.Checked == 2
        for row in range(table.rowCount()):
            chk = table.cellWidget(row, 0)
            if isinstance(chk, QCheckBox):
                chk.setChecked(checked)

    def _clean_all(self, table):
        """Quarantine all items from table."""
        row_count = table.rowCount()
        if row_count == 0:
            QMessageBox.information(self, "Clean All", "No items to clean.")
            return
        
        reply = QMessageBox.question(
            self,
            "Clean All",
            f"Are you sure you want to quarantine all {row_count} items?\n\n"
            "Files will be moved to quarantine folder safely.\n"
            "You can restore them later if needed.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            quarantined_count = 0
            failed_count = 0
            
            # Collect data before removing rows
            items_to_quarantine = []
            for row in range(row_count):
                try:
                    # Column 3 is Path (after checkbox at 0)
                    path_item = table.item(row, 3)
                    if path_item:
                        path = path_item.text()
                        
                        # Get other metadata
                        severity = table.item(row, 1).text() if table.item(row, 1) else 'UNKNOWN'
                        reason = table.item(row, 4).text() if table.item(row, 4) else 'No reason'
                        score = int(table.item(row, 5).text()) if table.item(row, 5) else 0
                        
                        items_to_quarantine.append({
                            'path': path,
                            'severity': severity,
                            'reason': reason,
                            'score': score
                        })
                except Exception:
                    pass
            
            # Quarantine each file
            for item in items_to_quarantine:
                result = self.quarantine_manager.quarantine_file(
                    item['path'],
                    item['reason'],
                    item['score'],
                    item['severity']
                )
                
                if result['success']:
                    quarantined_count += 1
                else:
                    failed_count += 1
            
            # Clear table
            table.setRowCount(0)
            
            # Show result
            msg = f"Successfully quarantined: {quarantined_count}\n"
            if failed_count > 0:
                msg += f"Failed: {failed_count}"
            
            QMessageBox.information(self, "Clean All", msg)

    def _clean_checked(self, table):
        """Quarantine checked items from table."""
        checked_rows = []
        for row in range(table.rowCount()):
            chk = table.cellWidget(row, 0)
            if isinstance(chk, QCheckBox) and chk.isChecked():
                checked_rows.append(row)
        
        if not checked_rows:
            QMessageBox.warning(self, "Clean Checked", "No items selected.")
            return
        
        reply = QMessageBox.question(
            self,
            "Clean Checked",
            f"Quarantine {len(checked_rows)} selected items?\n\n"
            "Files will be moved to quarantine safely.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            quarantined_count = 0
            failed_count = 0
            
            # Collect data before removing rows
            items_to_quarantine = []
            for row in checked_rows:
                try:
                    path_item = table.item(row, 3)
                    if path_item:
                        path = path_item.text()
                        severity = table.item(row, 1).text() if table.item(row, 1) else 'UNKNOWN'
                        reason = table.item(row, 4).text() if table.item(row, 4) else 'No reason'
                        score = int(table.item(row, 5).text()) if table.item(row, 5) else 0
                        
                        items_to_quarantine.append({
                            'path': path,
                            'severity': severity,
                            'reason': reason,
                            'score': score
                        })
                except Exception:
                    pass
            
            # Quarantine each file
            for item in items_to_quarantine:
                result = self.quarantine_manager.quarantine_file(
                    item['path'],
                    item['reason'],
                    item['score'],
                    item['severity']
                )
                
                if result['success']:
                    quarantined_count += 1
                else:
                    failed_count += 1
            
            # Remove rows in reverse order
            for row in reversed(checked_rows):
                table.removeRow(row)
            
            # Show result
            msg = f"Successfully quarantined: {quarantined_count}\n"
            if failed_count > 0:
                msg += f"Failed: {failed_count}"
            
            QMessageBox.information(self, "Clean Checked", msg)

    def _show_more_options(self):
        """Show additional options menu."""
        QMessageBox.information(
            self,
            "More Options",
            "Additional scanning and remediation options:\n\n"
            "- Deep scan\n"
            "- Export results\n"
            "- Schedule scan\n"
            "- Custom filters"
        )

    def _explore_selected(self, table):
        """Open file explorer for selected item."""
        import subprocess
        import os
        
        current_row = table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Explore", "Please select an item first.")
            return
        
        # Get path from column 3 (or adjust based on table)
        path_col = 3 if table.columnCount() == 7 else 3
        path_item = table.item(current_row, path_col)
        if path_item:
            file_path = path_item.text()
            if os.path.exists(file_path):
                folder = os.path.dirname(file_path)
                subprocess.Popen(f'explorer /select,"{file_path}"')
            else:
                QMessageBox.warning(self, "Explore", f"File not found: {file_path}")
        else:
            QMessageBox.warning(self, "Explore", "No path information available.")

    def _show_properties(self, table):
        """Show properties dialog for selected item."""
        import os
        
        current_row = table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Properties", "Please select an item first.")
            return
        
        # Gather all column data
        props = []
        for col in range(1, table.columnCount()):  # Skip checkbox column
            header = table.horizontalHeaderItem(col).text() if table.horizontalHeaderItem(col) else f"Col {col}"
            item = table.item(current_row, col)
            value = item.text() if item else "N/A"
            props.append(f"{header}: {value}")
        
        QMessageBox.information(
            self,
            "Properties",
            "\n".join(props)
        )
    
    def _terminate_process(self, table):
        """Terminate selected malicious process."""
        current_row = table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Terminate Process", "Please select a process first.")
            return
        
        # Get PID from table (assuming it's stored in a column)
        # For process results, we need to extract PID from the path/name column
        try:
            # Column 3 is typically the path/details column
            details_item = table.item(current_row, 3)
            if not details_item:
                QMessageBox.warning(self, "Terminate Process", "Cannot find process details.")
                return
            
            details = details_item.text()
            
            # Try to find PID in the details
            # If the threat is a process, it should have PID in the event dict
            # For now, we'll show a warning that this needs process PID
            
            reply = QMessageBox.question(
                self,
                "Terminate Process",
                f"Terminate this process?\n\n{details}\n\n"
                "⚠️ This will forcefully kill the process.",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # This would work if we had the PID stored
                # For now, show a placeholder
                QMessageBox.information(
                    self,
                    "Terminate Process",
                    "Process termination feature requires PID.\n"
                    "This will be implemented with process-specific detection."
                )
                
                # Future implementation:
                # pid = <extract from stored data>
                # result = self.process_terminator.terminate_process(pid, "Ransomware detected")
                # if result['success']:
                #     table.removeRow(current_row)
                #     QMessageBox.information(self, "Success", f"Process terminated: {result['name']}")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to terminate process: {str(e)}")
    
    def _on_row_double_clicked(self, item):
        """Show detailed threat information in a popup when row is double-clicked."""
        try:
            row = self.results_table.row(item)
            if row not in self.threat_data:
                return
            
            event = self.threat_data[row]
            
            # Create a simple, modeless dialog
            dialog = QDialog(None)  # No parent - true modeless window
            dialog.setWindowTitle("🔍 Threat Details")
            dialog.setGeometry(200, 200, 650, 550)
            dialog.setAttribute(Qt.WA_DeleteOnClose, True)
            
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(12, 12, 12, 12)
            layout.setSpacing(10)
            
            # Title
            title = QLabel(f"⚠️ {event.get('severity', 'UNKNOWN')} - {event.get('type', 'Unknown')}")
            title.setFont(QFont(FONT_FAMILY, FONT_SIZE_TITLE, QFont.Bold))
            layout.addWidget(title)
            
            # Details text area
            details = QTextEdit()
            details.setReadOnly(True)
            details.setFont(QFont("Consolas", 9))
            
            # Format details nicely
            detail_text = f"""
FILE/REGISTRY DETAILS
{'='*50}

Severity:        {event.get('severity', 'N/A')}
Type:            {event.get('type', 'N/A')}
Score:           {event.get('score', 0)}/200
Timestamp:       {event.get('timestamp', 'N/A')}

LOCATION
{'='*50}

Path:            {event.get('path', 'N/A')}
Extension:       {event.get('extension', 'N/A')}

ANALYSIS
{'='*50}

Detection Reason: {event.get('reason', 'N/A')}
Confidence:      {event.get('confidence', 'N/A')}

ADDITIONAL INFO
{'='*50}
"""
            
            # Add all other fields that might be present
            for key, value in event.items():
                if key not in ['severity', 'type', 'score', 'timestamp', 'path', 'extension', 'reason', 'confidence']:
                    detail_text += f"\n{key.replace('_', ' ').title()}: {str(value)[:100]}"
            
            details.setText(detail_text)
            layout.addWidget(details)
            
            # Button layout
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()
            
            # Copy button
            def copy_details():
                clipboard = __import__('PyQt5.QtWidgets').QApplication.clipboard()
                clipboard.setText(detail_text)
                QMessageBox.information(dialog, "Copied", "Details copied to clipboard!")
            
            copy_btn = QPushButton("📋 Copy Details")
            copy_btn.setMinimumHeight(36)
            copy_btn.clicked.connect(copy_details)
            btn_layout.addWidget(copy_btn)
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.setMinimumHeight(36)
            close_btn.setMinimumWidth(100)
            close_btn.clicked.connect(dialog.close)
            btn_layout.addWidget(close_btn)
            
            layout.addLayout(btn_layout)
            
            # Show as modeless window
            dialog.show()
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to show details: {str(e)}")

