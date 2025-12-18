import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from datetime import datetime
from tool import RansomwareEngine
from performance_monitor import PerformanceMonitor


class RansomwareGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Detection Tool")
        self.root.geometry("980x600")
        self.root.configure(bg="#0f1724")
        
        self.monitoring = False
        self.started_at = None
        self.total_logs = 0
        self.log_history = []
        
        # Performance monitoring
        self.perf_monitor = PerformanceMonitor(update_callback=self._update_perf_callback)
        
        self._setup_styles()
        self._build_ui()
        
        self.engine = RansomwareEngine(self.log_callback)
        
        self.update_controls()
        self.refresh_dashboard()
        self.root.after(500, self.auto_refresh)
        
        # Start performance monitoring
        if PerformanceMonitor.is_available():
            self.perf_monitor.start()
            if hasattr(self, 'perf_status_label'):
                self.perf_status_label.config(text="🟢 Performance Monitoring: Active", fg="#28c481")
    
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Notebook (tabs)
        style.configure('TNotebook', background="#0f1724", borderwidth=0)
        style.configure('TNotebook.Tab', background="#121c2b", foreground="#9fb6d0", 
                       padding=[14, 8], borderwidth=1, relief='flat')
        style.map('TNotebook.Tab', background=[('selected', '#1e2a3d')], 
                 foreground=[('selected', '#f3f8ff')])
        
        # Frame
        style.configure('TFrame', background="#0f1724")
        style.configure('Dark.TFrame', background="#121c2b")
        
        # LabelFrame
        style.configure('TLabelframe', background="#0b121f", bordercolor="#233246", 
                       relief='solid', borderwidth=1)
        style.configure('TLabelframe.Label', background="#0b121f", foreground="#9fb6d0", 
                       font=('Segoe UI', 9))
    
    def _build_ui(self):
        # Main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        
        # Dashboard tab
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self._build_dashboard()
        
        # Logs tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="Logs")
        self._build_logs()
        
        # Performance tab
        self.performance_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.performance_frame, text="Performance")
        self._build_performance()
    
    def _build_dashboard(self):
        # Header
        header_frame = tk.Frame(self.dashboard_frame, bg="#0f1724")
        header_frame.pack(fill=tk.X, padx=8, pady=(8, 10))
        
        title_frame = tk.Frame(header_frame, bg="#0f1724")
        title_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        title = tk.Label(title_frame, text="Ransomware Detection", 
                        font=('Segoe UI', 18, 'bold'), bg="#0f1724", fg="#e4edf7")
        title.pack(anchor=tk.W)
        
        subtitle = tk.Label(title_frame, text="Live monitoring and rapid response",
                          font=('Segoe UI', 9), bg="#0f1724", fg="#9fb6d0")
        subtitle.pack(anchor=tk.W)
        
        self.status_pill = tk.Label(header_frame, text="Stopped", 
                                   font=('Segoe UI', 9), bg="#2f1f25", fg="#f6c7d0",
                                   width=12, relief='flat')
        self.status_pill.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Buttons
        btn_frame = tk.Frame(self.dashboard_frame, bg="#0f1724")
        btn_frame.pack(fill=tk.X, padx=8, pady=5)
        
        self.start_btn = tk.Button(btn_frame, text="Start monitoring", 
                                   command=self.start_monitoring,
                                   bg="#7a2435", fg="#ffd5de", activebackground="#a33043",
                                   relief='flat', font=('Segoe UI', 9), padx=16, pady=10,
                                   cursor="hand2", borderwidth=1, highlightthickness=0)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = tk.Button(btn_frame, text="Stop", 
                                  command=self.stop_monitoring,
                                  bg="#7a2435", fg="#ffd5de", activebackground="#a33043",
                                  relief='flat', font=('Segoe UI', 9), padx=16, pady=10,
                                  cursor="hand2", borderwidth=1, highlightthickness=0)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.open_logs_btn = tk.Button(btn_frame, text="Open logs tab", 
                                       command=lambda: self.notebook.select(1),
                                       bg="#1f2f4a", fg="#d6e6ff", activebackground="#2f4c7a",
                                       relief='flat', font=('Segoe UI', 9), padx=16, pady=10,
                                       cursor="hand2", borderwidth=1, highlightthickness=0)
        self.open_logs_btn.pack(side=tk.LEFT)
        
        # Status label
        self.status_label = tk.Label(self.dashboard_frame, text="Status: Stopped",
                                     font=('Segoe UI', 9, 'bold'), bg="#0f1724", fg="#ff5c8a")
        self.status_label.pack(anchor=tk.W, padx=8, pady=5)
        
        # Stats group
        stats_frame = tk.LabelFrame(self.dashboard_frame, text="Quick stats",
                                   bg="#0b121f", fg="#9fb6d0", font=('Segoe UI', 9),
                                   relief='solid', borderwidth=1, padx=14, pady=12)
        stats_frame.pack(fill=tk.X, padx=8, pady=10)
        
        # Stats grid
        stats_labels = [
            ("Uptime:", 0),
            ("Logs received:", 1),
            ("Last event time:", 2)
        ]
        
        self.uptime_value = self._create_stat_row(stats_frame, "Uptime:", 0)
        self.logs_value = self._create_stat_row(stats_frame, "Logs received:", 1)
        self.last_event_value = self._create_stat_row(stats_frame, "Last event time:", 2)
        
        # Hint
        hint = tk.Label(self.dashboard_frame,
                       text="Tip: Keep monitoring running and switch to the Logs tab to inspect events.\n"
                            "Use 'Only alerts' or 'Contains' to filter noise.",
                       font=('Segoe UI', 9), bg="#0f1724", fg="#70809b", justify=tk.LEFT)
        hint.pack(anchor=tk.W, padx=8, pady=8)
    
    def _create_stat_row(self, parent, label_text, row):
        label = tk.Label(parent, text=label_text, 
                        font=('Segoe UI', 9, 'bold'), bg="#0b121f", fg="#9fb6d0")
        label.grid(row=row, column=0, sticky=tk.W, padx=(0, 18), pady=6)
        
        value = tk.Label(parent, text="—", 
                        font=('Consolas', 12), bg="#111a28", fg="#f4f7ff",
                        relief='flat', padx=10, pady=6)
        value.grid(row=row, column=1, sticky=tk.W, pady=6)
        
        parent.grid_columnconfigure(1, weight=3)
        
        return value
    
    def _build_logs(self):
        # Filters group
        filters_frame = tk.LabelFrame(self.logs_frame, text="Filters & actions",
                                     bg="#0b121f", fg="#9fb6d0", font=('Segoe UI', 9),
                                     relief='solid', borderwidth=1, padx=10, pady=10)
        filters_frame.pack(fill=tk.X, padx=8, pady=8)
        
        controls_frame = tk.Frame(filters_frame, bg="#0b121f")
        controls_frame.pack(fill=tk.X)
        
        self.clear_btn = tk.Button(controls_frame, text="Clear", command=self.clear_logs,
                                   bg="#1f2a3a", fg="#e4edf7", activebackground="#26344a",
                                   relief='flat', font=('Segoe UI', 9), padx=14, pady=8,
                                   cursor="hand2", borderwidth=1, highlightthickness=0)
        self.clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.copy_btn = tk.Button(controls_frame, text="Copy all", command=self.copy_all,
                                 bg="#1f2a3a", fg="#e4edf7", activebackground="#26344a",
                                 relief='flat', font=('Segoe UI', 9), padx=14, pady=8,
                                 cursor="hand2", borderwidth=1, highlightthickness=0)
        self.copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.only_alerts_var = tk.BooleanVar()
        self.only_alerts_chk = tk.Checkbutton(controls_frame, text="Only alerts",
                                             variable=self.only_alerts_var,
                                             command=self.apply_filters,
                                             bg="#0b121f", fg="#d9e5f4", 
                                             selectcolor="#1d7f5d", activebackground="#0b121f",
                                             font=('Segoe UI', 9), cursor="hand2")
        self.only_alerts_chk.pack(side=tk.LEFT, padx=(10, 10))
        
        tk.Label(controls_frame, text="Filter:", bg="#0b121f", fg="#d9e5f4",
                font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 5))
        
        self.contains_var = tk.StringVar()
        self.contains_entry = tk.Entry(controls_frame, textvariable=self.contains_var,
                                      bg="#0f1724", fg="#e4edf7", insertbackground="#e4edf7",
                                      relief='solid', borderwidth=1, font=('Segoe UI', 9))
        self.contains_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.contains_entry.bind('<Return>', lambda e: self.apply_filters())
        
        self.pause_view_var = tk.BooleanVar()
        self.pause_view_chk = tk.Checkbutton(controls_frame, text="Pause view",
                                            variable=self.pause_view_var,
                                            bg="#0b121f", fg="#d9e5f4",
                                            selectcolor="#1d7f5d", activebackground="#0b121f",
                                            font=('Segoe UI', 9), cursor="hand2")
        self.pause_view_chk.pack(side=tk.LEFT)
        
        # Info label
        info = tk.Label(self.logs_frame, text="Live event feed (alerts highlighted, newest at bottom)",
                       font=('Segoe UI', 9), bg="#0f1724", fg="#9fb6d0")
        info.pack(anchor=tk.W, padx=8, pady=(0, 5))
        
        # Log viewer
        log_frame = tk.Frame(self.logs_frame, bg="#2a3547", relief='solid', borderwidth=1)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        
        self.log_view = scrolledtext.ScrolledText(log_frame, bg="#0b111a", fg="#d3f0d3",
                                                 font=('Consolas', 10), relief='flat',
                                                 insertbackground="#d3f0d3", wrap=tk.NONE)
        self.log_view.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        self.log_view.tag_config('modified', foreground='#27ae60')
        self.log_view.tag_config('alert', foreground='#27ae60')
        self.log_view.tag_config('status', foreground='#f1c40f')
        self.log_view.tag_config('action', foreground='#e74c3c')
    
    def _build_performance(self):
        # Scrollable container
        canvas = tk.Canvas(self.performance_frame, bg="#0f1724", highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.performance_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#0f1724")
        
        def _on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        def _on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        scrollable_frame.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Header
        header_frame = tk.Frame(scrollable_frame, bg="#103a2a", relief='flat', bd=0)
        header_frame.pack(fill=tk.X, padx=8, pady=8)
        
        title = tk.Label(header_frame, text="📊 PERFORMANCE DASHBOARD",
                        font=('Segoe UI', 16, 'bold'), bg="#103a2a", fg="#ffffff")
        title.pack(anchor=tk.W, padx=15, pady=(12, 4))
        
        subtitle = tk.Label(header_frame, text="Real-time system metrics and process monitoring",
                           font=('Segoe UI', 9), bg="#103a2a", fg="#c5f6e2")
        subtitle.pack(anchor=tk.W, padx=15, pady=(0, 12))
        
        # Status bar
        status_bar = tk.Frame(scrollable_frame, bg="#0f1724")
        status_bar.pack(fill=tk.X, padx=8, pady=(0, 10))
        
        self.perf_status_label = tk.Label(status_bar, text="🟡 Performance Monitoring: Idle",
                                          font=('Segoe UI', 10, 'bold'), bg="#0f1724", fg="#f1c40f")
        self.perf_status_label.pack(side=tk.LEFT, padx=8)
        
        self.perf_last_update = tk.Label(status_bar, text="Last Update: --",
                                         font=('Segoe UI', 9), bg="#0f1724", fg="#9fb6d0")
        self.perf_last_update.pack(side=tk.RIGHT, padx=8)
        
        # KPI Cards Row 1
        kpi_frame1 = tk.Frame(scrollable_frame, bg="#0f1724")
        kpi_frame1.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)
        kpi_frame1.grid_columnconfigure(0, weight=1)
        kpi_frame1.grid_columnconfigure(1, weight=1)
        kpi_frame1.grid_columnconfigure(2, weight=1)
        kpi_frame1.grid_columnconfigure(3, weight=1)
        
        self.cpu_kpi = self._create_kpi_card_grid(kpi_frame1, "⚙️ CPU", "0%", "Processor", "#20B2AA", 0)
        self.mem_kpi = self._create_kpi_card_grid(kpi_frame1, "🧠 MEMORY", "0%", "RAM", "#FF8C00", 1)
        self.disk_kpi = self._create_kpi_card_grid(kpi_frame1, "💾 DISK", "0%", "Storage", "#DC143C", 2)
        self.tasks_kpi = self._create_kpi_card_grid(kpi_frame1, "⚡ TASKS", "0", "Processes", "#9370DB", 3)
        
        # Usage Bars Section
        usage_frame = tk.LabelFrame(scrollable_frame, text="System Overview",
                                   bg="#0b121f", fg="#9fb6d0", font=('Segoe UI', 9, 'bold'),
                                   relief='solid', borderwidth=1, padx=12, pady=10)
        usage_frame.pack(fill=tk.X, padx=8, pady=10)
        
        # CPU Bar
        cpu_bar_frame = tk.Frame(usage_frame, bg="#0b121f")
        cpu_bar_frame.pack(fill=tk.X, pady=5)
        tk.Label(cpu_bar_frame, text="CPU Usage:", font=('Segoe UI', 9, 'bold'),
                bg="#0b121f", fg="#9fb6d0", width=15, anchor=tk.W).pack(side=tk.LEFT, padx=(0, 10))
        self.cpu_bar = ttk.Progressbar(cpu_bar_frame, length=400, mode='determinate')
        self.cpu_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.cpu_bar_label = tk.Label(cpu_bar_frame, text="0%", font=('Consolas', 10, 'bold'),
                                      bg="#111a28", fg="#20B2AA", width=8, relief='flat', padx=5, pady=2)
        self.cpu_bar_label.pack(side=tk.LEFT)
        
        # Memory Bar
        mem_bar_frame = tk.Frame(usage_frame, bg="#0b121f")
        mem_bar_frame.pack(fill=tk.X, pady=5)
        tk.Label(mem_bar_frame, text="Memory Usage:", font=('Segoe UI', 9, 'bold'),
                bg="#0b121f", fg="#9fb6d0", width=15, anchor=tk.W).pack(side=tk.LEFT, padx=(0, 10))
        self.mem_bar = ttk.Progressbar(mem_bar_frame, length=400, mode='determinate')
        self.mem_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.mem_bar_label = tk.Label(mem_bar_frame, text="0%", font=('Consolas', 10, 'bold'),
                                      bg="#111a28", fg="#FF8C00", width=8, relief='flat', padx=5, pady=2)
        self.mem_bar_label.pack(side=tk.LEFT)
        
        # Disk Bar
        disk_bar_frame = tk.Frame(usage_frame, bg="#0b121f")
        disk_bar_frame.pack(fill=tk.X, pady=5)
        tk.Label(disk_bar_frame, text="Disk Usage:", font=('Segoe UI', 9, 'bold'),
                bg="#0b121f", fg="#9fb6d0", width=15, anchor=tk.W).pack(side=tk.LEFT, padx=(0, 10))
        self.disk_bar = ttk.Progressbar(disk_bar_frame, length=400, mode='determinate')
        self.disk_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.disk_bar_label = tk.Label(disk_bar_frame, text="0%", font=('Consolas', 10, 'bold'),
                                       bg="#111a28", fg="#DC143C", width=8, relief='flat', padx=5, pady=2)
        self.disk_bar_label.pack(side=tk.LEFT)
        
        # Details Section (CPU + Memory side by side)
        details_container = tk.Frame(scrollable_frame, bg="#0f1724")
        details_container.pack(fill=tk.X, padx=8, pady=5)
        
        # CPU Details
        cpu_details_frame = tk.LabelFrame(details_container, text="⚙️ CPU Details",
                                         bg="#0b121f", fg="#9fb6d0", font=('Segoe UI', 9, 'bold'),
                                         relief='solid', borderwidth=1, padx=10, pady=8)
        cpu_details_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.cpu_cores_label = self._create_detail_row(cpu_details_frame, "CPU Cores:", "0 cores")
        self.cpu_freq_label = self._create_detail_row(cpu_details_frame, "Frequency:", "0.00 GHz")
        self.cpu_temp_label = self._create_detail_row(cpu_details_frame, "Temperature:", "N/A")
        
        # Memory Details
        mem_details_frame = tk.LabelFrame(details_container, text="🧠 Memory Details",
                                         bg="#0b121f", fg="#9fb6d0", font=('Segoe UI', 9, 'bold'),
                                         relief='solid', borderwidth=1, padx=10, pady=8)
        mem_details_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.mem_total_label = self._create_detail_row(mem_details_frame, "Total:", "0 GB")
        self.mem_used_label = self._create_detail_row(mem_details_frame, "Used:", "0 GB")
        self.mem_available_label = self._create_detail_row(mem_details_frame, "Available:", "0 GB")
        
        # Disk Details
        disk_details_frame = tk.LabelFrame(scrollable_frame, text="💾 Disk Details",
                                          bg="#0b121f", fg="#9fb6d0", font=('Segoe UI', 9, 'bold'),
                                          relief='solid', borderwidth=1, padx=10, pady=8)
        disk_details_frame.pack(fill=tk.X, padx=8, pady=10)
        
        disk_row = tk.Frame(disk_details_frame, bg="#0b121f")
        disk_row.pack(fill=tk.X)
        self.disk_total_label = self._create_detail_row(disk_row, "Total:", "0 GB", side=tk.LEFT, expand=True)
        self.disk_used_label = self._create_detail_row(disk_row, "Used:", "0 GB", side=tk.LEFT, expand=True)
        self.disk_free_label = self._create_detail_row(disk_row, "Free:", "0 GB", side=tk.LEFT, expand=True)
        
        # Top Processes by CPU
        cpu_proc_frame = tk.LabelFrame(scrollable_frame, text="⚡ Top Processes by CPU",
                                      bg="#0b121f", fg="#9fb6d0", font=('Segoe UI', 9, 'bold'),
                                      relief='solid', borderwidth=1, padx=10, pady=8)
        cpu_proc_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)
        
        self.cpu_tree = self._create_process_table(cpu_proc_frame)
        
        # Top Processes by Memory
        mem_proc_frame = tk.LabelFrame(scrollable_frame, text="🧠 Top Processes by Memory",
                                      bg="#0b121f", fg="#9fb6d0", font=('Segoe UI', 9, 'bold'),
                                      relief='solid', borderwidth=1, padx=10, pady=8)
        mem_proc_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(5, 10))
        
        self.mem_tree = self._create_process_table(mem_proc_frame)
        
        # Bind mouse wheel for scrolling (only when mouse is over canvas)
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))
    
    def _create_kpi_card_grid(self, parent, title, value, subtitle, color, col):
        card = tk.Frame(parent, bg=color, relief='raised', bd=1)
        card.grid(row=0, column=col, sticky="nsew", padx=5, pady=5)
        
        tk.Label(card, text=title, font=('Segoe UI', 9, 'bold'),
                bg=color, fg="#ffffff").pack(anchor=tk.W, padx=10, pady=(8, 2))
        
        value_label = tk.Label(card, text=value, font=('Segoe UI', 22, 'bold'),
                              bg=color, fg="#ffffff")
        value_label.pack(pady=(2, 2))
        
        tk.Label(card, text=subtitle, font=('Segoe UI', 8),
                bg=color, fg="#f0f0f0").pack(anchor=tk.CENTER, padx=10, pady=(0, 8))
        
        return value_label
    
    def _create_detail_row(self, parent, label_text, value_text, side=None, expand=False):
        if side:
            row = tk.Frame(parent, bg="#0b121f")
            row.pack(side=side, fill=tk.X, expand=expand, padx=5)
        else:
            row = tk.Frame(parent, bg="#0b121f")
            row.pack(fill=tk.X, pady=3)
        
        tk.Label(row, text=label_text, font=('Segoe UI', 9, 'bold'),
                bg="#0b121f", fg="#9fb6d0", anchor=tk.W).pack(side=tk.LEFT, padx=(0, 8))
        
        value_label = tk.Label(row, text=value_text, font=('Consolas', 9),
                              bg="#111a28", fg="#f4f7ff", relief='flat', padx=8, pady=3)
        value_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        return value_label
    
    def _create_process_table(self, parent):
        tree = ttk.Treeview(parent, columns=('name', 'pid', 'cpu', 'mem'), show='headings', height=10)
        tree.heading('name', text='Process Name')
        tree.heading('pid', text='PID')
        tree.heading('cpu', text='CPU %')
        tree.heading('mem', text='Memory %')
        
        tree.column('name', width=250, anchor=tk.W)
        tree.column('pid', width=80, anchor=tk.CENTER)
        tree.column('cpu', width=80, anchor=tk.CENTER)
        tree.column('mem', width=80, anchor=tk.CENTER)
        
        tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Scrollbar
        tree_scroll = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        return tree
    
    # ---------- Logging ----------
    def log_callback(self, msg: str):
        self.total_logs += 1
        self.log_history.append(msg)
        self.last_event_value.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        if self.pause_view_var.get():
            return
        
        if not self._passes_filters(msg):
            return
        
        self.log_view.insert(tk.END, msg + "\n")
        tags = self._log_tags(msg)
        if tags:
            self.log_view.insert(tk.END, msg + "\n", tags)
        else:
            self.log_view.insert(tk.END, msg + "\n")
        self.log_view.see(tk.END)

    def _log_tags(self, msg: str):
        m = msg.lower()
        if 'alert' in m:
            return ('alert',)
        if 'modified' in m:
            return ('modified',)
        if 'status' in m:
            return ('status',)
        if 'action' in m:
            return ('action',)
        return ()
    
    def _passes_filters(self, msg: str) -> bool:
        if self.only_alerts_var.get():
            keywords = ("alert", "warning", "danger", "blocked", "ransom", "malware", "suspicious")
            if not any(k in msg.lower() for k in keywords):
                return False
        
        text = self.contains_var.get().strip()
        if text and (text.lower() not in msg.lower()):
            return False
        
        return True
    
    def apply_filters(self):
        self.log_view.delete('1.0', tk.END)
        for line in self.log_history:
            if self._passes_filters(line):
                tags = self._log_tags(line)
                if tags:
                    self.log_view.insert(tk.END, line + "\n", tags)
                else:
                    self.log_view.insert(tk.END, line + "\n")
        self.log_view.see(tk.END)
    
    def clear_logs(self):
        self.log_view.delete('1.0', tk.END)
        self.total_logs = 0
        self.log_history.clear()
        self.last_event_value.config(text="—")
        self.refresh_dashboard()
    
    def copy_all(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_view.get('1.0', tk.END))
    
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
    
    def update_controls(self):
        if self.monitoring:
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
        else:
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
    
    def refresh_dashboard(self):
        if self.monitoring:
            self.status_label.config(text="Status: Monitoring", fg="#f1c40f")
            self.status_pill.config(text="Monitoring", bg="#4c3f00", fg="#ffe680")
        else:
            self.status_label.config(text="Status: Stopped", fg="#f1c40f")
            self.status_pill.config(text="Stopped", bg="#4c3f00", fg="#ffe680")
        
        self.logs_value.config(text=str(self.total_logs))
        
        if self.monitoring and self.started_at:
            delta = datetime.now() - self.started_at
            total_s = int(delta.total_seconds())
            h = total_s // 3600
            m = (total_s % 3600) // 60
            s = total_s % 60
            self.uptime_value.config(text=f"{h:02d}:{m:02d}:{s:02d}")
        else:
            self.uptime_value.config(text="—")
    
    def auto_refresh(self):
        self.refresh_dashboard()
        self.root.after(500, self.auto_refresh)
    
    def on_close(self):
        # Stop performance monitoring
        if hasattr(self, 'perf_monitor'):
            self.perf_monitor.stop()
            if hasattr(self, 'perf_status_label'):
                self.perf_status_label.config(text="🟡 Performance Monitoring: Idle", fg="#f1c40f")
        
        if self.monitoring:
            if messagebox.askyesno("Exit", "Monitoring is running. Stop and exit?"):
                self.stop_monitoring()
                self.root.destroy()
        else:
            self.root.destroy()
    
    # ---------- Performance update hooks ----------
    def _update_perf_callback(self, **kwargs):
        """Callback for performance monitor (called from background thread)"""
        # Update UI using after() to avoid threading issues
        self.root.after(0, lambda: self.update_performance(**kwargs))
    
    def update_performance(self, cpu_pct=0, mem_pct=0, disk_pct=0, tasks=0,
                          cpu_details=None, mem_details=None, disk_details=None,
                          top_cpu_processes=None, top_mem_processes=None):
        """Update all performance metrics. Call this with real data from monitoring."""
        # Update KPI cards
        self.cpu_kpi.config(text=f"{cpu_pct}%")
        self.mem_kpi.config(text=f"{mem_pct}%")
        self.disk_kpi.config(text=f"{disk_pct}%")
        self.tasks_kpi.config(text=str(tasks))
        
        # Update progress bars
        self.cpu_bar['value'] = cpu_pct
        self.cpu_bar_label.config(text=f"{cpu_pct}%")
        self.mem_bar['value'] = mem_pct
        self.mem_bar_label.config(text=f"{mem_pct}%")
        self.disk_bar['value'] = disk_pct
        self.disk_bar_label.config(text=f"{disk_pct}%")
        
        # Update CPU details
        if cpu_details:
            self.cpu_cores_label.config(text=cpu_details.get('cores', '0 cores'))
            self.cpu_freq_label.config(text=cpu_details.get('freq', '0.00 GHz'))
            self.cpu_temp_label.config(text=cpu_details.get('temp', 'N/A'))
        
        # Update Memory details
        if mem_details:
            self.mem_total_label.config(text=mem_details.get('total', '0 GB'))
            self.mem_used_label.config(text=mem_details.get('used', '0 GB'))
            self.mem_available_label.config(text=mem_details.get('available', '0 GB'))
        
        # Update Disk details
        if disk_details:
            self.disk_total_label.config(text=disk_details.get('total', '0 GB'))
            self.disk_used_label.config(text=disk_details.get('used', '0 GB'))
            self.disk_free_label.config(text=disk_details.get('free', '0 GB'))
        
        # Update top CPU processes
        if top_cpu_processes:
            self.cpu_tree.delete(*self.cpu_tree.get_children())
            for proc in top_cpu_processes[:10]:  # Top 10
                self.cpu_tree.insert('', tk.END, values=(
                    proc.get('name', 'N/A'),
                    proc.get('pid', '0'),
                    f"{proc.get('cpu', 0):.1f}",
                    f"{proc.get('mem', 0):.1f}"
                ))
        
        # Update top Memory processes
        if top_mem_processes:
            self.mem_tree.delete(*self.mem_tree.get_children())
            for proc in top_mem_processes[:10]:  # Top 10
                self.mem_tree.insert('', tk.END, values=(
                    proc.get('name', 'N/A'),
                    proc.get('pid', '0'),
                    f"{proc.get('cpu', 0):.1f}",
                    f"{proc.get('mem', 0):.1f}"
                ))
        
        # Update status and timestamp
        self.perf_last_update.config(text=f"Last Update: {datetime.now().strftime('%H:%M:%S')}")


def main():
    root = tk.Tk()
    app = RansomwareGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()