"""
Performance Monitoring Tab - Real-time performance dashboard.
"""

from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QGroupBox, QFormLayout, QProgressBar, QScrollArea, QFrame, QAbstractItemView
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


def _build_status_header(main_window, container):
    status_frame = QFrame()
    status_layout = QHBoxLayout(status_frame)
    status_layout.setContentsMargins(0, 0, 0, 0)
    status_layout.setSpacing(10)

    status_label = QLabel("🟡 Performance Monitoring Idle")
    status_label.setFont(QFont("Arial", 11, QFont.Bold))
    status_label.setStyleSheet("color: #f39c12;")

    last_update = QLabel("Last Update: --")
    last_update.setFont(QFont("Arial", 10))
    last_update.setStyleSheet("color: #777;")

    status_layout.addWidget(status_label)
    status_layout.addStretch()
    status_layout.addWidget(last_update)

    container.addWidget(status_frame)

    main_window.perf_labels['status'] = status_label
    main_window.perf_labels['last_update'] = last_update


def _build_overview_group(main_window, container):
    overview_group = QGroupBox("🔍 SYSTEM OVERVIEW")
    overview_group.setStyleSheet(
        """
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
        """
    )
    overview_form = QFormLayout(overview_group)
    overview_form.setSpacing(12)
    overview_form.setContentsMargins(15, 15, 15, 15)

    # CPU Usage
    cpu_label = QLabel("CPU Usage:")
    cpu_label.setFont(QFont("Arial", 11, QFont.Bold))
    cpu_bar = QProgressBar()
    cpu_bar.setMaximum(100)
    cpu_bar.setValue(0)
    cpu_bar.setMinimumHeight(30)
    cpu_bar.setStyleSheet(
        """
        QProgressBar {
            border: 2px solid #ddd;
            border-radius: 6px;
            background-color: #f5f5f5;
            height: 30px;
        }
        QProgressBar::chunk {
            background-color: #32b8c6;
            border-radius: 4px;
        }
        """
    )
    cpu_text = QLabel("0%")
    cpu_text.setFont(QFont("Arial", 12, QFont.Bold))
    cpu_text.setStyleSheet("color: #32b8c6; min-width: 60px;")
    cpu_row = QHBoxLayout()
    cpu_row.addWidget(cpu_bar, 1)
    cpu_row.addWidget(cpu_text)
    overview_form.addRow(cpu_label, cpu_row)

    # Memory Usage
    mem_label = QLabel("Memory Usage:")
    mem_label.setFont(QFont("Arial", 11, QFont.Bold))
    mem_bar = QProgressBar()
    mem_bar.setMaximum(100)
    mem_bar.setValue(0)
    mem_bar.setMinimumHeight(30)
    mem_bar.setStyleSheet(
        """
        QProgressBar {
            border: 2px solid #ddd;
            border-radius: 6px;
            background-color: #f5f5f5;
            height: 30px;
        }
        QProgressBar::chunk {
            background-color: #f39c12;
            border-radius: 4px;
        }
        """
    )
    mem_text = QLabel("0%")
    mem_text.setFont(QFont("Arial", 12, QFont.Bold))
    mem_text.setStyleSheet("color: #f39c12; min-width: 70px;")
    mem_row = QHBoxLayout()
    mem_row.addWidget(mem_bar, 1)
    mem_row.addWidget(mem_text)
    overview_form.addRow(mem_label, mem_row)

    # Disk Usage
    disk_label = QLabel("Disk Usage:")
    disk_label.setFont(QFont("Arial", 11, QFont.Bold))
    disk_bar = QProgressBar()
    disk_bar.setMaximum(100)
    disk_bar.setValue(0)
    disk_bar.setMinimumHeight(30)
    disk_bar.setStyleSheet(
        """
        QProgressBar {
            border: 2px solid #ddd;
            border-radius: 6px;
            background-color: #f5f5f5;
            height: 30px;
        }
        QProgressBar::chunk {
            background-color: #e74c3c;
            border-radius: 4px;
        }
        """
    )
    disk_text = QLabel("0%")
    disk_text.setFont(QFont("Arial", 12, QFont.Bold))
    disk_text.setStyleSheet("color: #e74c3c; min-width: 70px;")
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


def _build_cpu_group(main_window, container):
    cpu_group = QGroupBox("⚙️ CPU DETAILS")
    cpu_group.setStyleSheet(
        """
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
        """
    )
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

    container.addWidget(cpu_group)

    main_window.perf_labels.update({
        'cpu_cores': cpu_cores,
        'cpu_freq': cpu_freq,
        'cpu_temp': cpu_temp,
    })


def _build_memory_group(main_window, container):
    mem_group = QGroupBox("🧠 MEMORY DETAILS")
    mem_group.setStyleSheet(
        """
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
        """
    )
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

    container.addWidget(mem_group)

    main_window.perf_labels.update({
        'mem_total': mem_total,
        'mem_used': mem_used,
        'mem_available': mem_available,
    })


def _build_disk_group(main_window, container):
    disk_group = QGroupBox("💾 DISK DETAILS")
    disk_group.setStyleSheet(
        """
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
        """
    )
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


def _build_process_tables(main_window, container):
    # Top CPU processes
    cpu_group = QGroupBox("⚡ TOP PROCESSES BY CPU")
    cpu_group.setStyleSheet(
        """
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
        """
    )
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
    table_cpu.setStyleSheet(
        """
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
            background-color: #32b8c6;
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
        """
    )
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
    table_memory.setStyleSheet(table_cpu.styleSheet())
    mem_layout.addWidget(table_memory)
    container.addWidget(mem_group)

    main_window.perf_labels.update({
        'table_cpu': table_cpu,
        'table_memory': table_memory,
    })


def create_performance_tab(main_window):
    """Create comprehensive performance monitoring tab."""
    # Ensure dictionary exists
    if not hasattr(main_window, 'perf_labels'):
        main_window.perf_labels = {}

    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(15, 15, 15, 15)
    layout.setSpacing(15)

    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setStyleSheet("QScrollArea { border: none; background-color: #f5f5f5; }")

    content_widget = QWidget()
    content_layout = QVBoxLayout(content_widget)
    content_layout.setSpacing(30)
    content_layout.setContentsMargins(15, 15, 15, 15)
    content_widget.setStyleSheet("background-color: #f5f5f5;")

    # Build sections
    _build_status_header(main_window, content_layout)
    _build_overview_group(main_window, content_layout)
    _build_cpu_group(main_window, content_layout)
    _build_memory_group(main_window, content_layout)
    _build_disk_group(main_window, content_layout)
    _build_process_tables(main_window, content_layout)

    content_layout.addStretch()

    scroll.setWidget(content_widget)
    layout.addWidget(scroll)

    return widget
