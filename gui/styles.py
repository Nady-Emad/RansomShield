"""
Professional stylesheets and UI constants
"""

# Color Scheme (Professional Teal/Red Theme)
COLOR_PRIMARY = "#0FA3B1"      # Teal accent
COLOR_PRIMARY_DARK = "#0D8A99" # Dark teal
COLOR_PRIMARY_LIGHT = "#E0F7FA"  # Light teal bg
COLOR_SUCCESS = "#27AE60"      # Green
COLOR_WARNING = "#F39C12"      # Orange
COLOR_CRITICAL = "#E74C3C"     # Red
COLOR_INFO = "#3498DB"         # Blue
COLOR_BG_LIGHT = "#F5F5F5"     # Light gray bg
COLOR_BG_DARK = "#FFFFFF"      # White (card bg)
COLOR_TEXT_DARK = "#2C3E50"    # Dark gray text
COLOR_TEXT_LIGHT = "#7F8C8D"   # Light gray text
COLOR_BORDER = "#E0E0E0"       # Border gray

# Font Configuration
FONT_FAMILY = "Segoe UI"
FONT_SIZE_TITLE = 14
FONT_SIZE_SUBTITLE = 12
FONT_SIZE_BODY = 11
FONT_SIZE_SMALL = 10

# Spacing
SPACING_XXS = 4
SPACING_XS = 8
SPACING_SM = 12
SPACING_MD = 16
SPACING_LG = 20
SPACING_XL = 24

# Border Radius
RADIUS_SMALL = "4px"
RADIUS_MEDIUM = "6px"
RADIUS_LARGE = "8px"

# Shadow
SHADOW = "0 2px 4px rgba(0, 0, 0, 0.1)"

# Professional Stylesheet
STYLESHEET = f"""
/* ========== MAIN WINDOW ========== */
QMainWindow {{
    background-color: {COLOR_BG_LIGHT};
}}

QMainWindow::separator {{
    background-color: {COLOR_BORDER};
}}

/* ========== TAB WIDGET ========== */
QTabWidget::pane {{
    border: 0px solid {COLOR_BORDER};
    background-color: {COLOR_BG_DARK};
    margin-top: -1px;
}}

QTabBar {{
    background-color: {COLOR_BG_LIGHT};
    border-bottom: 0px solid {COLOR_BORDER};
    padding: 6px 8px;
}}

QTabBar::tab {{
    background-color: {COLOR_BG_LIGHT};
    color: {COLOR_TEXT_DARK};
    padding: 16px 36px;
    margin: 3px 6px;
    border: none;
    border-bottom: 3px solid transparent;
    font-weight: 600;
    font-size: {FONT_SIZE_SUBTITLE + 2}px;
    min-height: 44px;
    min-width: 140px;
    /* Qt stylesheets do not support CSS transitions or letter-spacing */
}}

QTabBar::tab:hover:!selected {{
    background-color: #F0F0F0;
    border-bottom: 3px solid {COLOR_BORDER};
}}

QTabBar::tab:selected {{
    color: white;
    background-color: {COLOR_PRIMARY};
    border-bottom: 3px solid {COLOR_PRIMARY};
}}

/* ========== BUTTONS ========== */
QPushButton {{
    background-color: {COLOR_PRIMARY};
    color: white;
    border: none;
    padding: 10px 16px;
    border-radius: {RADIUS_MEDIUM};
    font-weight: 600;
    font-size: {FONT_SIZE_BODY}px;
}}

QPushButton:hover {{
    background-color: {COLOR_PRIMARY_DARK};
    padding: 10px 18px; /* Padding change is supported */
}}

QPushButton:pressed {{
    background-color: #087A88;
    padding: 10px 15px;
}}

QPushButton#danger {{
    background-color: {COLOR_CRITICAL};
}}

QPushButton#danger:hover {{
    background-color: #C0392B;
}}

QPushButton#success {{
    background-color: {COLOR_SUCCESS};
}}

QPushButton#success:hover {{
    background-color: #229954;
}}

QPushButton#secondary {{
    background-color: {COLOR_BG_LIGHT};
    color: {COLOR_TEXT_DARK};
    border: 2px solid {COLOR_BORDER};
}}

QPushButton#secondary:hover {{
    border: 2px solid {COLOR_PRIMARY};
    background-color: #FAFAFA;
}}

/* ========== GROUP BOX ========== */
QGroupBox {{
    color: {COLOR_TEXT_DARK};
    border: 2px solid {COLOR_BORDER};
    border-radius: {RADIUS_MEDIUM};
    margin-top: 10px;
    padding-top: 12px;
    font-weight: 600;
    font-size: {FONT_SIZE_BODY}px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    margin-left: 8px;
}}

/* ========== LABELS ========== */
QLabel {{
    color: {COLOR_TEXT_DARK};
    font-family: "{FONT_FAMILY}";
}}

/* ========== TEXT INPUT ========== */
QLineEdit {{
    background-color: {COLOR_BG_DARK};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_SMALL};
    padding: 8px 12px;
    color: {COLOR_TEXT_DARK};
    font-size: {FONT_SIZE_BODY}px;
    selection-background-color: {COLOR_PRIMARY};
}}

QLineEdit:focus {{
    border: 2px solid {COLOR_PRIMARY};
    padding: 8px 11px;
}}

/* ========== TEXT EDIT ========== */
QTextEdit {{
    background-color: {COLOR_BG_DARK};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_SMALL};
    color: {COLOR_TEXT_DARK};
    font-size: {FONT_SIZE_BODY}px;
}}

QTextEdit:focus {{
    border: 2px solid {COLOR_PRIMARY};
}}

/* ========== COMBO BOX ========== */
QComboBox {{
    background-color: {COLOR_BG_DARK};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_SMALL};
    padding: 6px 10px;
    color: {COLOR_TEXT_DARK};
    font-size: {FONT_SIZE_BODY}px;
}}

QComboBox:hover {{
    border: 1px solid {COLOR_PRIMARY};
}}

QComboBox::drop-down {{
    border: none;
    background-color: {COLOR_PRIMARY};
    border-radius: 0 {RADIUS_SMALL} {RADIUS_SMALL} 0;
}}

QComboBox QAbstractItemView {{
    background-color: {COLOR_BG_DARK};
    selection-background-color: {COLOR_PRIMARY};
    color: {COLOR_TEXT_DARK};
}}

/* ========== SPIN BOX ========== */
QSpinBox {{
    background-color: {COLOR_BG_DARK};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_SMALL};
    padding: 6px;
    color: {COLOR_TEXT_DARK};
}}

QSpinBox:focus {{
    border: 2px solid {COLOR_PRIMARY};
}}

QSpinBox::up-button, QSpinBox::down-button {{
    background-color: {COLOR_PRIMARY};
    border: none;
}}

/* ========== CHECKBOX ========== */
QCheckBox {{
    spacing: 8px;
    color: {COLOR_TEXT_DARK};
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border: 2px solid {COLOR_BORDER};
    border-radius: {RADIUS_SMALL};
    background-color: {COLOR_BG_DARK};
}}

QCheckBox::indicator:hover {{
    border: 2px solid {COLOR_PRIMARY};
}}

QCheckBox::indicator:checked {{
    background-color: {COLOR_PRIMARY};
    border: 2px solid {COLOR_PRIMARY};
}}

/* ========== TABLES ========== */
QTableWidget {{
    background-color: {COLOR_BG_DARK};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_MEDIUM};
    gridline-color: #F0F0F0;
}}

QTableWidget::item {{
    padding: 8px;
    height: 36px;
}}

QTableWidget::item:alternated-background {{
    background-color: #FAFAFA;
}}

QHeaderView::section {{
    background-color: {COLOR_PRIMARY};
    color: white;
    padding: 10px;
    border: none;
    font-weight: 600;
    font-size: {FONT_SIZE_BODY}px;
    height: 40px;
}}

QTableWidget::item:selected {{
    background-color: {COLOR_PRIMARY_LIGHT};
}}

/* ========== SCROLL AREA ========== */
QScrollArea {{
    border: 1px solid {COLOR_BORDER};
    background-color: transparent;
    border-radius: {RADIUS_SMALL};
}}

QScrollBar:vertical {{
    background-color: {COLOR_BG_LIGHT};
    width: 12px;
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
}}

QScrollBar::handle:vertical {{
    background-color: {COLOR_PRIMARY};
    border-radius: 6px;
    min-height: 20px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLOR_PRIMARY_DARK};
}}

/* ========== FRAME ========== */
QFrame {{
    background-color: {COLOR_BG_DARK};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_MEDIUM};
}}

/* ========== MENU BAR ========== */
QMenuBar {{
    background-color: {COLOR_BG_LIGHT};
    color: {COLOR_TEXT_DARK};
    border-bottom: 1px solid {COLOR_BORDER};
}}

QMenuBar::item:selected {{
    background-color: {COLOR_PRIMARY};
    color: white;
}}

QMenu {{
    background-color: {COLOR_BG_DARK};
    color: {COLOR_TEXT_DARK};
    border: 1px solid {COLOR_BORDER};
}}

QMenu::item:selected {{
    background-color: {COLOR_PRIMARY};
    color: white;
}}

/* ========== TOOL BAR ========== */
QToolBar {{
    background-color: {COLOR_BG_LIGHT};
    border-bottom: 1px solid {COLOR_BORDER};
    padding: 8px;
    spacing: 8px;
}}

QToolBar::separator {{
    background-color: {COLOR_BORDER};
    margin: 0 4px;
}}

/* ========== PROGRESS BAR ========== */
QProgressBar {{
    border: 2px solid {COLOR_BORDER};
    border-radius: {RADIUS_MEDIUM};
    background-color: #F0F0F0;
    height: 28px;
    text-align: center;
    color: {COLOR_TEXT_DARK};
    font-weight: 600;
}}

QProgressBar::chunk {{
    background-color: {COLOR_PRIMARY};
    border-radius: {RADIUS_MEDIUM};
}}
"""

# Severity Styles
SEVERITY_STYLES = {
    'CRITICAL': {
        'bg_color': COLOR_CRITICAL,
        'text_color': 'white',
        'icon': '🔴',
        'border_color': '#C0392B'
    },
    'WARNING': {
        'bg_color': COLOR_WARNING,
        'text_color': '#000000',
        'icon': '🟡',
        'border_color': '#D68910'
    },
    'INFO': {
        'bg_color': COLOR_INFO,
        'text_color': 'white',
        'icon': '🔵',
        'border_color': '#2980B9'
    },
    'SUCCESS': {
        'bg_color': COLOR_SUCCESS,
        'text_color': 'white',
        'icon': '✓',
        'border_color': '#229954'
    }
}

# Card Stylesheet
CARD_STYLESHEET = f"""
QFrame {{
    background-color: {COLOR_BG_DARK};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_LARGE};
    padding: 16px;
}}
"""

# Status Indicator Styles
STATUS_INDICATOR_RUNNING = f"""
    border-radius: 50%;
    background-color: {COLOR_SUCCESS};
    width: 12px;
    height: 12px;
"""

STATUS_INDICATOR_STOPPED = f"""
    border-radius: 50%;
    background-color: {COLOR_CRITICAL};
    width: 12px;
    height: 12px;
"""

STATUS_INDICATOR_WARNING = f"""
    border-radius: 50%;
    background-color: {COLOR_WARNING};
    width: 12px;
    height: 12px;
"""
