"""Professional custom dialogs with enhanced UX"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QProgressBar,
    QGridLayout, QFrame
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QIcon, QColor

from gui.styles import (
    COLOR_PRIMARY, COLOR_CRITICAL, COLOR_SUCCESS, COLOR_WARNING, COLOR_BG_LIGHT,
    COLOR_TEXT_DARK, FONT_FAMILY, FONT_SIZE_SUBTITLE, FONT_SIZE_BODY,
    SEVERITY_STYLES
)


class CriticalAlertDialog(QDialog):
    """Professional critical alert dialog with Block/Allow actions."""
    
    def __init__(self, title, message, event_data=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setGeometry(100, 50, 850, 700)  # أكبر قليلاً
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BG_LIGHT};
            }}
        """)
        
        self.event_data = event_data or {}
        self.user_action = None  # 'block', 'allow', or None
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Header with icon and title
        header_layout = QHBoxLayout()
        
        icon_label = QLabel("⚠️")
        icon_label.setFont(QFont(FONT_FAMILY, 48))
        icon_label.setStyleSheet(f"color: {COLOR_CRITICAL};")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setMinimumWidth(80)
        header_layout.addWidget(icon_label)
        
        # Title and subtitle
        title_layout = QVBoxLayout()
        
        title_label = QLabel(title)
        title_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE + 4, QFont.Bold))
        title_label.setStyleSheet(f"color: {COLOR_CRITICAL};")
        title_layout.addWidget(title_label)
        
        subtitle = QLabel("Immediate action required")
        subtitle.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY + 2))
        subtitle.setStyleSheet(f"color: {COLOR_TEXT_DARK};")
        title_layout.addWidget(subtitle)
        
        title_layout.addStretch()
        header_layout.addLayout(title_layout)
        layout.addLayout(header_layout)
        
        # Separator
        separator = QLabel()
        separator.setStyleSheet(f"background-color: {COLOR_CRITICAL}; height: 3px;")
        layout.addWidget(separator)
        
        # Message area - بشكل منظم مثل Event Details
        details_frame = QFrame()
        details_frame.setStyleSheet(f"""
            QFrame {{
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 6px;
            }}
        """)
        details_layout = QGridLayout(details_frame)
        details_layout.setSpacing(12)
        details_layout.setContentsMargins(14, 14, 14, 14)
        
        # Helper function to create detail rows
        def add_detail_row(label_text, value_text, row):
            label = QLabel(label_text)
            label.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY + 1, QFont.Bold))
            label.setStyleSheet("color: #333;")
            
            value = QLabel(value_text or "N/A")
            value.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY + 1))
            value.setStyleSheet("color: #666;")
            value.setWordWrap(True)
            
            details_layout.addWidget(label, row, 0, 1, 1)
            details_layout.addWidget(value, row, 1, 1, 1)
        
        # Add all details
        row = 0
        add_detail_row("🔴 Severity:", self.event_data.get('severity', 'N/A'), row)
        
        row += 1
        add_detail_row("📋 Rule:", self.event_data.get('rule', 'N/A'), row)
        
        row += 1
        add_detail_row("📁 File Path:", self.event_data.get('path', 'N/A'), row)
        
        row += 1
        add_detail_row("🎯 Process ID:", str(self.event_data.get('pid', 'N/A')), row)
        
        row += 1
        add_detail_row("🔧 Process Name:", self.event_data.get('process_name', 'N/A'), row)
        
        row += 1
        score = self.event_data.get('score', 'N/A')
        score_text = f"{score}/250"
        add_detail_row("⚡ Risk Score:", score_text, row)
        
        row += 1
        add_detail_row("✓ Action:", self.event_data.get('action', 'N/A'), row)
        
        row += 1
        add_detail_row("⏰ Timestamp:", self.event_data.get('timestamp', 'N/A'), row)
        
        row += 1
        add_detail_row("💬 Message:", self.event_data.get('message', 'N/A'), row)
        
        details_layout.setColumnStretch(1, 1)
        layout.addWidget(details_frame)
        
        # Action buttons layout
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        # Block button (blacklist)
        btn_block = QPushButton("🚫 Block Process (Blacklist)")
        btn_block.setMinimumWidth(220)
        btn_block.setMinimumHeight(45)
        btn_block.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY + 1, QFont.Bold))
        btn_block.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CRITICAL};
                color: white;
                padding: 12px 20px;
                border-radius: 6px;
                font-weight: bold;
                border: none;
                font-size: 12pt;
            }}
            QPushButton:hover {{
                background-color: #C0392B;
            }}
            QPushButton:pressed {{
                background-color: #922B21;
            }}
        """)
        btn_block.clicked.connect(lambda: self._on_action('block'))
        btn_layout.addWidget(btn_block)
        
        # Allow button (whitelist)
        btn_allow = QPushButton("✅ Allow Process (Whitelist)")
        btn_allow.setMinimumWidth(220)
        btn_allow.setMinimumHeight(45)
        btn_allow.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY + 1, QFont.Bold))
        btn_allow.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_SUCCESS};
                color: white;
                padding: 12px 20px;
                border-radius: 6px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #27AE60;
            }}
            QPushButton:pressed {{
                background-color: #1E8449;
            }}
        """)
        btn_allow.clicked.connect(lambda: self._on_action('allow'))
        btn_layout.addWidget(btn_allow)
        
        # Acknowledge button (no list change)
        btn_ack = QPushButton("⏭️ Acknowledge Only")
        btn_ack.setMinimumWidth(200)
        btn_ack.setMinimumHeight(45)
        btn_ack.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY + 1))
        btn_ack.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_WARNING};
                color: white;
                padding: 12px 20px;
                border-radius: 6px;
                font-weight: normal;
                border: none;
                font-size: 11pt;
            }}
            QPushButton:hover {{
                background-color: #D68910;
            }}
            QPushButton:pressed {{
                background-color: #B9770E;
            }}
        """)
        btn_ack.clicked.connect(lambda: self._on_action(None))
        btn_layout.addWidget(btn_ack)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        self.exec_()
    
    def _on_action(self, action):
        """Handle user action."""
        self.user_action = action
        self.accept()


class SuccessDialog(QDialog):
    """Success dialog with animated checkmark."""
    
    def __init__(self, title, message, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setGeometry(100, 100, 500, 300)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BG_LIGHT};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Icon
        icon_label = QLabel("✓")
        icon_label.setFont(QFont(FONT_FAMILY, 56, QFont.Bold))
        icon_label.setStyleSheet(f"color: {COLOR_SUCCESS};")
        icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_label)
        
        # Title
        title_label = QLabel(title)
        title_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE + 1, QFont.Bold))
        title_label.setStyleSheet(f"color: {COLOR_TEXT_DARK};")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Message
        msg_label = QLabel(message)
        msg_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        msg_label.setStyleSheet(f"color: {COLOR_TEXT_DARK};")
        msg_label.setAlignment(Qt.AlignCenter)
        msg_label.setWordWrap(True)
        layout.addWidget(msg_label)
        
        layout.addStretch()
        
        # Button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        btn_ok = QPushButton("✓ OK")
        btn_ok.setMinimumWidth(140)
        btn_ok.setMinimumHeight(40)
        btn_ok.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY, QFont.Bold))
        btn_ok.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_SUCCESS};
                color: white;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                border: none;
            }}
            QPushButton:hover {{
                background-color: #229954;
            }}
            QPushButton:pressed {{
                background-color: #1E8449;
            }}
        """)
        btn_ok.clicked.connect(self.accept)
        btn_layout.addWidget(btn_ok)
        
        layout.addLayout(btn_layout)
        
        self.exec_()


class ProgressDialog(QDialog):
    """Modal dialog with progress bar."""
    
    def __init__(self, title, message, total_steps=100, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setGeometry(200, 200, 500, 200)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BG_LIGHT};
            }}
        """)
        self.setWindowFlags(self.windowFlags() | Qt.FramelessWindowHint)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Title
        title_label = QLabel(title)
        title_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
        title_label.setStyleSheet(f"color: {COLOR_TEXT_DARK};")
        layout.addWidget(title_label)
        
        # Message
        msg_label = QLabel(message)
        msg_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        msg_label.setStyleSheet(f"color: {COLOR_TEXT_DARK};")
        layout.addWidget(msg_label)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setMaximum(total_steps)
        self.progress.setValue(0)
        self.progress.setMinimumHeight(24)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid #ddd;
                border-radius: 6px;
                background-color: #f5f5f5;
                text-align: center;
                color: {COLOR_TEXT_DARK};
                font-weight: 600;
            }}
            QProgressBar::chunk {{
                background-color: {COLOR_PRIMARY};
                border-radius: 4px;
            }}
        """)
        layout.addWidget(self.progress)
        
        layout.addStretch()
    
    def update_progress(self, value):
        """Update progress bar."""
        self.progress.setValue(value)


class WarningDialog(QDialog):
    """Warning dialog with customizable actions."""
    
    def __init__(self, title, message, buttons=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setGeometry(100, 100, 550, 350)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BG_LIGHT};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Header
        header_layout = QHBoxLayout()
        
        icon_label = QLabel("⚠️")
        icon_label.setFont(QFont(FONT_FAMILY, 40))
        icon_label.setStyleSheet(f"color: {COLOR_WARNING};")
        icon_label.setMinimumWidth(60)
        header_layout.addWidget(icon_label)
        
        title_label = QLabel(title)
        title_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE + 1, QFont.Bold))
        title_label.setStyleSheet(f"color: {COLOR_TEXT_DARK};")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Message
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY))
        text_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 6px;
                padding: 12px;
                color: {COLOR_TEXT_DARK};
            }}
        """)
        text_edit.setText(message)
        layout.addWidget(text_edit)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        if buttons is None:
            buttons = [("Continue", 1), ("Cancel", 0)]
        
        for btn_text, btn_value in buttons:
            btn = QPushButton(btn_text)
            btn.setMinimumWidth(120)
            btn.setMinimumHeight(40)
            btn.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY, QFont.Bold))
            btn.clicked.connect(lambda checked, val=btn_value: self.done(val))
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLOR_PRIMARY};
                    color: white;
                    padding: 10px 20px;
                    border-radius: 6px;
                    font-weight: bold;
                    border: none;
                }}
                QPushButton:hover {{
                    background-color: #0D8A99;
                }}
                QPushButton:pressed {{
                    background-color: #087A88;
                }}
            """)
            btn_layout.addWidget(btn)
        
        layout.addLayout(btn_layout)
        
        self.result_value = self.exec_()
