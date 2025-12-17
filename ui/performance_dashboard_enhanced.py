"""
Enhanced Performance Dashboard - Professional UI with gradients and modern styling.
Drop-in replacement for performance_tab.py with enterprise-grade design.
"""

from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QGroupBox, QFormLayout, QProgressBar, QScrollArea, QFrame, QAbstractItemView
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QLinearGradient, QPainter


class GradientCard(QFrame):
    """Professional gradient card for KPI metrics."""
    
    def __init__(self, title, value, subtitle, color_start, color_end):
        super().__init__()
        self.title = title
        self.value = value
        self.subtitle = subtitle
        self.color_start = color_start
        self.color_end = color_end
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        
        # Title
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 11, QFont.Bold))
        title_label.setStyleSheet("color: #666;")
        layout.addWidget(title_label)
        
        # Value
        value_label = QLabel(value)
        value_label.setFont(QFont("Arial", 32, QFont.Bold))
        value_label.setStyleSheet("color: white;")
        value_label.setAlignment(Qt.AlignCenter)
        self.value_label = value_label
        layout.addWidget(value_label)
        
        # Subtitle
        sub_label = QLabel(subtitle)
        sub_label.setFont(QFont("Arial", 10))
        sub_label.setStyleSheet("color: rgba(255, 255, 255, 0.8);")
        sub_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(sub_label)
        
        layout.addStretch()
        
        # Set gradient background
        self.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {color_start}, stop:1 {color_end});
                border: none;
                border-radius: 12px;
            }}
        """)
        
        self.setMinimumHeight(160)
        self.setMaximumHeight(160)


def _build_kpi_cards(main_window, container):
    """Build 6 professional gradient KPI cards."""
    # First row - 4 cards
    cards_layout1 = QHBoxLayout()
    cards_layout1.setSpacing(15)
    
    # CPU Card
    cpu_card = GradientCard(
        "⚙️ CPU",
        "0%",
        "Processor",
        "#20B2AA",  # Light Sea Green
        "#008B8B"   # Dark Cyan
    )
    main_window.perf_labels['cpu_card'] = cpu_card.value_label
    cards_layout1.addWidget(cpu_card)
    
    # Memory Card
    mem_card = GradientCard(
        "🧠 MEMORY",
        "0%",
        "RAM",
        "#FF8C00",  # Dark Orange
        "#FF6347"   # Tomato
    )
    main_window.perf_labels['mem_card'] = mem_card.value_label
    cards_layout1.addWidget(mem_card)
    
    # Disk Card
    disk_card = GradientCard(
        "💾 DISK",
        "0%",
        "Storage",
        "#DC143C",  # Crimson
        "#B22222"   # Fire Brick
    )
    main_window.perf_labels['disk_card'] = disk_card.value_label
    cards_layout1.addWidget(disk_card)
    
    # Processes Card
    proc_card = GradientCard(
        "⚡ TASKS",
        "0",
        "Processes",
        "#9370DB",  # Medium Purple
        "#8A2BE2"   # Blue Violet
    )
    main_window.perf_labels['proc_card'] = proc_card.value_label
    cards_layout1.addWidget(proc_card)
    
    # First row container
    cards_frame1 = QFrame()
    cards_frame1.setLayout(cards_layout1)
    container.addWidget(cards_frame1)
    
    # Second row - 2 cards (Network & GPU)
    cards_layout2 = QHBoxLayout()
    cards_layout2.setSpacing(15)
    
    # Network Card
    net_card = GradientCard(
        "🌐 NETWORK",
        "0 KB/s",
        "Download/Upload",
        "#1E90FF",  # Dodger Blue
        "#4169E1"   # Royal Blue
    )
    main_window.perf_labels['net_card'] = net_card.value_label
    cards_layout2.addWidget(net_card)
    
    # GPU Card
    gpu_card = GradientCard(
        "🎮 GPU",
        "N/A",
        "Graphics",
        "#FF1493",  # Deep Pink
        "#C71585"   # Medium Violet Red
    )
    main_window.perf_labels['gpu_card'] = gpu_card.value_label
    cards_layout2.addWidget(gpu_card)
    
    # Second row container
    cards_frame2 = QFrame()
    cards_frame2.setLayout(cards_layout2)
    container.addWidget(cards_frame2)


def _build_overview_group(main_window, container):
    """Build system overview section."""
    overview_group = QGroupBox("🔍 SYSTEM OVERVIEW")
    overview_group.setStyleSheet("""
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
    overview_form = QFormLayout(overview_group)
    overview_form.setSpacing(12)
    overview_form.setContentsMargins(15, 15, 15, 15)

    # CPU Usage Bar
    cpu_label = QLabel("CPU Usage:")
    cpu_label.setFont(QFont("Arial", 11, QFont.Bold))
    cpu_bar = QProgressBar()
    cpu_bar.setMaximum(100)
    cpu_bar.setValue(0)
    cpu_bar.setMinimumHeight(30)
    cpu_bar.setStyleSheet("""
        QProgressBar {
            border: 2px solid #ddd;
            border-radius: 6px;
            background-color: #f5f5f5;
            height: 30px;
        }
        QProgressBar::chunk {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #20B2AA, stop:1 #008B8B);
            border-radius: 4px;
        }
    """)
    cpu_text = QLabel("0%")
    cpu_text.setFont(QFont("Arial", 12, QFont.Bold))
    cpu_text.setStyleSheet("color: #20B2AA; min-width: 60px;")
    cpu_row = QHBoxLayout()
    cpu_row.addWidget(cpu_bar, 1)
    cpu_row.addWidget(cpu_text)
    overview_form.addRow(cpu_label, cpu_row)

    # Memory Usage Bar
    mem_label = QLabel("Memory Usage:")
    mem_label.setFont(QFont("Arial", 11, QFont.Bold))
    mem_bar = QProgressBar()
    mem_bar.setMaximum(100)
    mem_bar.setValue(0)
    mem_bar.setMinimumHeight(30)
    mem_bar.setStyleSheet("""
        QProgressBar {
            border: 2px solid #ddd;
            border-radius: 6px;
            background-color: #f5f5f5;
            height: 30px;
        }
        QProgressBar::chunk {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #FF8C00, stop:1 #FF6347);
            border-radius: 4px;
        }
    """)
    mem_text = QLabel("0%")
    mem_text.setFont(QFont("Arial", 12, QFont.Bold))
    mem_text.setStyleSheet("color: #FF8C00; min-width: 70px;")
    mem_row = QHBoxLayout()
    mem_row.addWidget(mem_bar, 1)
    mem_row.addWidget(mem_text)
    overview_form.addRow(mem_label, mem_row)

    # Disk Usage Bar
    disk_label = QLabel("Disk Usage:")
    disk_label.setFont(QFont("Arial", 11, QFont.Bold))
    disk_bar = QProgressBar()
    disk_bar.setMaximum(100)
    disk_bar.setValue(0)
    disk_bar.setMinimumHeight(30)
    disk_bar.setStyleSheet("""
        QProgressBar {
            border: 2px solid #ddd;
            border-radius: 6px;
            background-color: #f5f5f5;
            height: 30px;
        }
        QProgressBar::chunk {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #DC143C, stop:1 #B22222);
            border-radius: 4px;
        }
    """)
    disk_text = QLabel("0%")
    disk_text.setFont(QFont("Arial", 12, QFont.Bold))
    disk_text.setStyleSheet("color: #DC143C; min-width: 70px;")
    disk_row = QHBoxLayout()
    disk_row.addWidget(disk_bar, 1)
    disk_row.addWidget(disk_text)
    overview_form.addRow(disk_label, disk_row)

    container.addWidget(overview_group)

    main_window.perf_labels.update({
        'cpu_bar': cpu_bar,
        'cpu_text': cpu_text,
        'mem_bar': mem_bar,
        'mem_text': mem_text,
        'disk_bar': disk_bar,
        'disk_text': disk_text,
    })


def _build_details_group(main_window, container):
    """Build CPU and Memory details."""
    details_layout = QHBoxLayout()
    details_layout.setSpacing(15)

    # CPU Details
    cpu_group = QGroupBox("⚙️ CPU DETAILS")
    cpu_group.setStyleSheet("""
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
    cpu_form = QFormLayout(cpu_group)
    cpu_form.setSpacing(12)
    cpu_form.setContentsMargins(15, 15, 15, 15)

    cpu_cores = QLabel("0 cores")
    cpu_cores.setFont(QFont("Arial", 11))
    cpu_cores.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    cpu_form.addRow("CPU Cores:", cpu_cores)

    cpu_freq = QLabel("0.00 GHz")
    cpu_freq.setFont(QFont("Arial", 11))
    cpu_freq.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    cpu_form.addRow("CPU Frequency:", cpu_freq)

    cpu_temp = QLabel("N/A")
    cpu_temp.setFont(QFont("Arial", 11))
    cpu_temp.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    cpu_form.addRow("CPU Temperature:", cpu_temp)

    details_layout.addWidget(cpu_group)

    # Memory Details
    mem_group = QGroupBox("🧠 MEMORY DETAILS")
    mem_group.setStyleSheet(cpu_group.styleSheet())
    mem_form = QFormLayout(mem_group)
    mem_form.setSpacing(12)
    mem_form.setContentsMargins(15, 15, 15, 15)

    mem_total = QLabel("0 GB")
    mem_total.setFont(QFont("Arial", 11))
    mem_total.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    mem_form.addRow("Total Memory:", mem_total)

    mem_used = QLabel("0 GB")
    mem_used.setFont(QFont("Arial", 11))
    mem_used.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    mem_form.addRow("Used Memory:", mem_used)

    mem_available = QLabel("0 GB")
    mem_available.setFont(QFont("Arial", 11))
    mem_available.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    mem_form.addRow("Available Memory:", mem_available)

    details_layout.addWidget(mem_group)

    details_frame = QFrame()
    details_frame.setLayout(details_layout)
    container.addWidget(details_frame)

    main_window.perf_labels.update({
        'cpu_cores': cpu_cores,
        'cpu_freq': cpu_freq,
        'cpu_temp': cpu_temp,
        'mem_total': mem_total,
        'mem_used': mem_used,
        'mem_available': mem_available,
    })


def _build_disk_group(main_window, container):
    """Build disk details group."""
    disk_group = QGroupBox("💾 DISK DETAILS")
    disk_group.setStyleSheet("""
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
    disk_form = QFormLayout(disk_group)
    disk_form.setSpacing(12)
    disk_form.setContentsMargins(15, 15, 15, 15)

    disk_total = QLabel("0 GB")
    disk_total.setFont(QFont("Arial", 11))
    disk_total.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    disk_form.addRow("Total Space:", disk_total)

    disk_used = QLabel("0 GB")
    disk_used.setFont(QFont("Arial", 11))
    disk_used.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    disk_form.addRow("Used Space:", disk_used)

    disk_free = QLabel("0 GB")
    disk_free.setFont(QFont("Arial", 11))
    disk_free.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    disk_form.addRow("Free Space:", disk_free)

    container.addWidget(disk_group)

    main_window.perf_labels.update({
        'disk_total': disk_total,
        'disk_used': disk_used,
        'disk_free': disk_free,
    })


def _build_network_gpu_group(main_window, container):
    """Build network and GPU details."""
    details_layout = QHBoxLayout()
    details_layout.setSpacing(15)

    # Network Details
    net_group = QGroupBox("🌐 NETWORK DETAILS")
    net_group.setStyleSheet("""
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
    net_form = QFormLayout(net_group)
    net_form.setSpacing(12)
    net_form.setContentsMargins(15, 15, 15, 15)

    net_download = QLabel("0 KB/s")
    net_download.setFont(QFont("Arial", 11))
    net_download.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    net_form.addRow("Download:", net_download)

    net_upload = QLabel("0 KB/s")
    net_upload.setFont(QFont("Arial", 11))
    net_upload.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    net_form.addRow("Upload:", net_upload)

    net_total = QLabel("0 KB/s")
    net_total.setFont(QFont("Arial", 11))
    net_total.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    net_form.addRow("Total Speed:", net_total)

    details_layout.addWidget(net_group)

    # GPU Details
    gpu_group = QGroupBox("🎮 GPU DETAILS")
    gpu_group.setStyleSheet(net_group.styleSheet())
    gpu_form = QFormLayout(gpu_group)
    gpu_form.setSpacing(12)
    gpu_form.setContentsMargins(15, 15, 15, 15)

    gpu_load = QLabel("N/A")
    gpu_load.setFont(QFont("Arial", 11))
    gpu_load.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    gpu_form.addRow("GPU Load:", gpu_load)

    gpu_temp = QLabel("N/A")
    gpu_temp.setFont(QFont("Arial", 11))
    gpu_temp.setStyleSheet("color: #555; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    gpu_form.addRow("GPU Temp:", gpu_temp)

    gpu_status = QLabel("Not Available")
    gpu_status.setFont(QFont("Arial", 11))
    gpu_status.setStyleSheet("color: #888; padding: 8px; background: #f9f9f9; border-radius: 4px;")
    gpu_form.addRow("Status:", gpu_status)

    details_layout.addWidget(gpu_group)

    details_frame = QFrame()
    details_frame.setLayout(details_layout)
    container.addWidget(details_frame)

    main_window.perf_labels.update({
        'net_download': net_download,
        'net_upload': net_upload,
        'net_total': net_total,
        'gpu_load': gpu_load,
        'gpu_temp': gpu_temp,
        'gpu_status': gpu_status,
    })


def _build_process_tables(main_window, container):
    """Build top processes tables."""
    # Top CPU processes
    cpu_group = QGroupBox("⚡ TOP PROCESSES BY CPU")
    cpu_group.setStyleSheet("""
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
    cpu_layout = QVBoxLayout(cpu_group)
    cpu_layout.setContentsMargins(15, 15, 15, 15)

    table_cpu = QTableWidget()
    table_cpu.setColumnCount(4)
    table_cpu.setHorizontalHeaderLabels(["Process Name", "PID", "CPU %", "Memory %"])
    table_cpu.setAlternatingRowColors(True)
    table_cpu.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table_cpu.setSelectionMode(QAbstractItemView.NoSelection)
    table_cpu.setColumnWidth(0, 230)
    table_cpu.setColumnWidth(1, 80)
    table_cpu.setColumnWidth(2, 80)
    table_cpu.setColumnWidth(3, 90)
    table_cpu.setMinimumHeight(600)
    table_cpu.setStyleSheet("""
        QTableWidget {
            background-color: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            gridline-color: #f0f0f0;
        }
        QTableWidget::item {
            padding: 12px;
            height: 42px;
        }
        QTableWidget::item:alternated-background {
            background-color: #f9f9f9;
        }
        QHeaderView::section {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #20B2AA, stop:1 #008B8B);
            color: white;
            padding: 12px;
            border: none;
            font-weight: bold;
            font-size: 11px;
            height: 40px;
        }
        QTableWidget::item:selected {
            background-color: #d4f1f7;
        }
    """)
    cpu_layout.addWidget(table_cpu)
    container.addWidget(cpu_group)

    # Top memory processes
    mem_group = QGroupBox("🧠 TOP PROCESSES BY MEMORY")
    mem_group.setStyleSheet(cpu_group.styleSheet())
    mem_layout = QVBoxLayout(mem_group)
    mem_layout.setContentsMargins(15, 15, 15, 15)

    table_memory = QTableWidget()
    table_memory.setColumnCount(4)
    table_memory.setHorizontalHeaderLabels(["Process Name", "PID", "Memory %", "CPU %"])
    table_memory.setAlternatingRowColors(True)
    table_memory.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table_memory.setSelectionMode(QAbstractItemView.NoSelection)
    table_memory.setColumnWidth(0, 230)
    table_memory.setColumnWidth(1, 80)
    table_memory.setColumnWidth(2, 90)
    table_memory.setColumnWidth(3, 80)
    table_memory.setMinimumHeight(600)
    table_memory.setStyleSheet("""
        QTableWidget {
            background-color: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            gridline-color: #f0f0f0;
        }
        QTableWidget::item {
            padding: 12px;
            height: 42px;
        }
        QTableWidget::item:alternated-background {
            background-color: #f9f9f9;
        }
        QHeaderView::section {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #FF8C00, stop:1 #FF6347);
            color: white;
            padding: 12px;
            border: none;
            font-weight: bold;
            font-size: 11px;
            height: 40px;
        }
        QTableWidget::item:selected {
            background-color: #fff3e0;
        }
    """)
    mem_layout.addWidget(table_memory)
    container.addWidget(mem_group)

    main_window.perf_labels.update({
        'table_cpu': table_cpu,
        'table_memory': table_memory,
    })


def create_performance_tab(main_window):
    """Create professional performance dashboard with enhanced styling."""
    if not hasattr(main_window, 'perf_labels'):
        main_window.perf_labels = {}

    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(15, 15, 15, 15)
    layout.setSpacing(15)

    # Header
    header_frame = QFrame()
    header_frame.setStyleSheet("""
        QFrame {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #20B2AA, stop:1 #008B8B);
            border-radius: 8px;
        }
    """)
    header_layout = QVBoxLayout(header_frame)
    header_layout.setContentsMargins(20, 20, 20, 20)

    header_title = QLabel("📊 PERFORMANCE DASHBOARD")
    header_title.setFont(QFont("Arial", 16, QFont.Bold))
    header_title.setStyleSheet("color: white;")
    header_layout.addWidget(header_title)

    header_subtitle = QLabel("Real-time system metrics and process monitoring")
    header_subtitle.setFont(QFont("Arial", 11))
    header_subtitle.setStyleSheet("color: rgba(255, 255, 255, 0.9);")
    header_layout.addWidget(header_subtitle)

    layout.addWidget(header_frame)

    # Scrollable content
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setStyleSheet("QScrollArea { border: none; background-color: #f5f5f5; }")

    content_widget = QWidget()
    content_layout = QVBoxLayout(content_widget)
    content_layout.setSpacing(30)
    content_layout.setContentsMargins(15, 15, 15, 15)
    content_widget.setStyleSheet("background-color: #f5f5f5;")

    # Build sections
    _build_kpi_cards(main_window, content_layout)
    _build_overview_group(main_window, content_layout)
    _build_details_group(main_window, content_layout)
    _build_disk_group(main_window, content_layout)
    _build_network_gpu_group(main_window, content_layout)
    _build_process_tables(main_window, content_layout)

    content_layout.addStretch()

    scroll.setWidget(content_widget)
    layout.addWidget(scroll)

    # Footer
    footer_frame = QFrame()
    footer_frame.setStyleSheet("""
        QFrame {
            background-color: #f0f0f0;
            border-radius: 6px;
        }
    """)
    footer_layout = QHBoxLayout(footer_frame)
    footer_layout.setContentsMargins(15, 10, 15, 10)

    status_label = QLabel("🟡 Performance Monitoring Idle")
    status_label.setFont(QFont("Arial", 11, QFont.Bold))
    status_label.setStyleSheet("color: #f39c12;")
    footer_layout.addWidget(status_label)

    footer_layout.addStretch()

    last_update = QLabel("Last Update: --")
    last_update.setFont(QFont("Arial", 10))
    last_update.setStyleSheet("color: #777;")
    footer_layout.addWidget(last_update)

    layout.addWidget(footer_frame)

    main_window.perf_labels['status'] = status_label
    main_window.perf_labels['last_update'] = last_update

    return widget
