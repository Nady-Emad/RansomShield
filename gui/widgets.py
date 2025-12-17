"""Professional custom PyQt5 widgets with animations and enhanced UX"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QFrame, 
    QGraphicsOpacityEffect
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, pyqtProperty
from PyQt5.QtGui import QFont, QColor, QIcon
# Optional charts: guard import for environments without QtChart
try:
    from PyQt5.QtChart import QChart, QChartView, QPieSeries, QPieSlice
except Exception:
    QChart = None
    QChartView = QWidget  # fallback to simple QWidget
    QPieSeries = None
    QPieSlice = None

from gui.styles import (
    COLOR_PRIMARY, COLOR_SUCCESS, COLOR_WARNING, COLOR_CRITICAL, COLOR_INFO,
    COLOR_BG_DARK, COLOR_TEXT_DARK, COLOR_TEXT_LIGHT, COLOR_BORDER,
    FONT_FAMILY, FONT_SIZE_BODY, FONT_SIZE_SUBTITLE, SEVERITY_STYLES
)


class AnimatedCard(QFrame):
    """Enhanced card widget with shadow and hover effects."""
    
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.NoFrame)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLOR_BG_DARK};
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 12)
        
        # Title
        if title:
            title_label = QLabel(title)
            title_label.setFont(QFont(FONT_FAMILY, FONT_SIZE_SUBTITLE, QFont.Bold))
            title_label.setStyleSheet(f"color: {COLOR_TEXT_DARK};")
            layout.addWidget(title_label)
    
    def add_widget(self, widget):
        """Add widget to card content."""
        self.layout().addWidget(widget)


class StatusCard(QFrame):
    """Status card widget with professional styling."""
    
    def __init__(self, title, value, color_code='info', parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.NoFrame)
        self.color_code = color_code
        self._setup_colors()
        self._setup_ui(title, value)
    
    def _setup_colors(self):
        """Setup color based on code."""
        color_map = {
            'critical': COLOR_CRITICAL,
            'warning': COLOR_WARNING,
            'success': COLOR_SUCCESS,
            'info': COLOR_INFO
        }
        self.color = color_map.get(self.color_code, COLOR_INFO)
    
    def _setup_ui(self, title, value):
        """Setup UI components."""
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLOR_BG_DARK};
                border: 2px solid {self.color};
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(12, 12, 12, 12)
        
        # Title
        lbl_title = QLabel(title)
        lbl_title.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY, QFont.Bold))
        lbl_title.setStyleSheet(f"color: {COLOR_TEXT_LIGHT};")
        layout.addWidget(lbl_title)
        
        # Value
        self.lbl_value = QLabel(value)
        self.lbl_value.setFont(QFont(FONT_FAMILY, 18, QFont.Bold))
        self.lbl_value.setStyleSheet(f"color: {self.color};")
        layout.addWidget(self.lbl_value)
    
    def set_value(self, value):
        """Update card value with animation."""
        self.lbl_value.setText(str(value))
        self._animate_value()
    
    def _animate_value(self):
        """Add subtle pulse animation to value."""
        effect = QGraphicsOpacityEffect()
        self.lbl_value.setGraphicsEffect(effect)
        
        animation = QPropertyAnimation(effect, b"opacity")
        animation.setDuration(300)
        animation.setStartValue(0.7)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        animation.start()


class SeverityBadge(QLabel):
    """Color-coded severity badge with professional styling."""
    
    def __init__(self, severity='INFO', parent=None):
        super().__init__(parent)
        self.set_severity(severity)
        self.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY, QFont.Bold))
        self.setAlignment(Qt.AlignCenter)
    
    def set_severity(self, severity):
        """Update severity and styling."""
        style_info = SEVERITY_STYLES.get(severity, SEVERITY_STYLES['INFO'])
        
        self.setText(f"{style_info['icon']} {severity}")
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {style_info['bg_color']};
                color: {style_info['text_color']};
                padding: 6px 12px;
                border-radius: 6px;
                border: 1px solid {style_info['border_color']};
                font-weight: 600;
            }}
        """)


class RiskMeter(QWidget):
    """Advanced visual risk meter with color transitions."""
    
    def __init__(self, max_score=200, parent=None):
        super().__init__(parent)
        self.max_score = max_score
        self.current_score = 0
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup risk meter UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Title
        lbl = QLabel("Risk Score")
        lbl.setFont(QFont(FONT_FAMILY, FONT_SIZE_BODY, QFont.Bold))
        lbl.setStyleSheet(f"color: {COLOR_TEXT_DARK};")
        layout.addWidget(lbl)
        
        # Progress bar with professional styling
        self.progress = QProgressBar()
        self.progress.setMaximum(self.max_score)
        self.progress.setValue(0)
        self.progress.setMinimumHeight(32)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid {COLOR_BORDER};
                border-radius: 8px;
                background-color: #F5F5F5;
                text-align: center;
                color: {COLOR_TEXT_DARK};
                font-weight: 600;
            }}
            QProgressBar::chunk {{
                background-color: {COLOR_SUCCESS};
                border-radius: 6px;
            }}
        """)
        layout.addWidget(self.progress)
        
        # Score label
        self.lbl_score = QLabel("0 / 200")
        self.lbl_score.setFont(QFont(FONT_FAMILY, 12, QFont.Bold))
        self.lbl_score.setAlignment(Qt.AlignCenter)
        self.lbl_score.setStyleSheet(f"""
            QLabel {{
                color: {COLOR_SUCCESS};
                background-color: #F0F9F8;
                padding: 8px;
                border-radius: 6px;
                border: 1px solid {COLOR_BORDER};
            }}
        """)
        layout.addWidget(self.lbl_score)
    
    def set_score(self, score):
        """Update risk score with color transition."""
        self.current_score = min(score, self.max_score)
        self.progress.setValue(int(self.current_score))
        self.lbl_score.setText(f"{int(self.current_score)} / {self.max_score}")
        
        # Determine colors based on risk level
        if self.current_score < 50:
            chunk_color = COLOR_SUCCESS
            bg_color = "#F0F9F8"
            text_color = COLOR_SUCCESS
        elif self.current_score < 120:
            chunk_color = COLOR_WARNING
            bg_color = "#FFF3E0"
            text_color = COLOR_WARNING
        else:
            chunk_color = COLOR_CRITICAL
            bg_color = "#FFE6E6"
            text_color = COLOR_CRITICAL
        
        # Apply colors with smooth transition
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid {COLOR_BORDER};
                border-radius: 8px;
                background-color: #F5F5F5;
                text-align: center;
                color: {COLOR_TEXT_DARK};
                font-weight: 600;
            }}
            QProgressBar::chunk {{
                background-color: {chunk_color};
                border-radius: 6px;
            }}
        """)
        
        self.lbl_score.setStyleSheet(f"""
            QLabel {{
                color: {text_color};
                background-color: {bg_color};
                padding: 8px;
                border-radius: 6px;
                border: 1px solid {COLOR_BORDER};
                font-weight: 600;
            }}
        """)
    
    def get_risk_level(self):
        """Get current risk level as string."""
        if self.current_score < 50:
            return "LOW"
        elif self.current_score < 120:
            return "MEDIUM"
        else:
            return "HIGH"


class EventChart(QChartView):
    """Professional pie chart for event distribution (optional)."""
    
    def __init__(self, parent=None):
        if QChart is None:
            super().__init__(parent)
            placeholder = QLabel("Charts unavailable (QtChart not installed)")
            placeholder.setAlignment(Qt.AlignCenter)
            layout = QVBoxLayout(self)
            layout.addWidget(placeholder)
            return
        chart = QChart()
        chart.setTitle("Event Distribution")
        chart.setBackgroundBrush(QColor(COLOR_BG_DARK))
        chart.setTitleBrush(QColor(COLOR_TEXT_DARK))
        chart.legend().setVisible(True)
        super().__init__(chart, parent)
        self.setRenderHint(self.Antialiasing)
    
    def update_data(self, critical, warning, info):
        if QPieSeries is None:
            return
        series = QPieSeries()
        if critical > 0:
            slice_critical = QPieSlice("Critical", critical)
            slice_critical.setColor(QColor(COLOR_CRITICAL))
            slice_critical.setLabelVisible(True)
            series.append(slice_critical)
        if warning > 0:
            slice_warning = QPieSlice("Warning", warning)
            slice_warning.setColor(QColor(COLOR_WARNING))
            slice_warning.setLabelVisible(True)
            series.append(slice_warning)
        if info > 0:
            slice_info = QPieSlice("Info", info)
            slice_info.setColor(QColor(COLOR_INFO))
            slice_info.setLabelVisible(True)
            series.append(slice_info)
        self.chart().removeAllSeries()
        self.chart().addSeries(series)


class Toast(QWidget):
    """Simple toast notification anchored to a parent window."""

    def __init__(self, parent=None, message="", duration_ms=2500, severity="INFO"):
        super().__init__(parent)
        self.setWindowFlags(self.windowFlags() | Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)

        # Colors per severity
        style = SEVERITY_STYLES.get(severity, SEVERITY_STYLES['INFO'])

        frame = QFrame(self)
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {style['bg_color']};
                border-radius: 8px;
                border: 2px solid {style['border_color']};
            }}
        """)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        icon = QLabel(style['icon'])
        icon.setStyleSheet("color: white;")
        icon.setFont(QFont(FONT_FAMILY, 12, QFont.Bold))
        layout.addWidget(icon)
        msg = QLabel(message)
        msg.setStyleSheet("color: white;")
        msg.setFont(QFont(FONT_FAMILY, 11))
        layout.addWidget(msg)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(frame)

        # Auto-hide timer
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.close)
        self._duration = duration_ms

    def show_near_parent_bottom_right(self):
        """Position toast near bottom-right of parent and show."""
        parent = self.parent()
        if parent is None:
            self.show()
            self._timer.start(self._duration)
            return
        parent_rect = parent.geometry()
        self.adjustSize()
        w = self.width()
        h = self.height()
        # 24px margin from edges
        x = parent_rect.x() + parent_rect.width() - w - 24
        y = parent_rect.y() + parent_rect.height() - h - 24
        self.setGeometry(x, y, w, h)
        self.show()
        self._timer.start(self._duration)
