import tkinter as tk
from tkinter import ttk
import threading
import time
from typing import List, Dict, Optional, Callable

class Dashboard:
    def __init__(self, root, alert_provider, firewall_provider):
        self.root = root
        self.alert_provider = alert_provider
        self.firewall_provider = firewall_provider
        
        self.root.title("IPS Dashboard")
        self.root.geometry("1000x600")
        
        self.setup_ui()
        
        # Set up refresh timer
        self.refresh_interval = 5  # seconds
        self.should_refresh = True
        self.refresh_thread = threading.Thread(target=self._refresh_loop)
        self.refresh_thread.daemon = True
        self.refresh_thread.start()
    
    def setup_ui(self):
        # Create a notebook with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Alerts
        self.alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_frame, text="Alerts")
        self._setup_alerts_tab()
        
        # Tab 2: Firewall Rules
        self.firewall_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.firewall_frame, text="Firewall Rules")
        self._setup_firewall_tab()
        
        # Tab 3: System Status
        self.status_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.status_frame, text="System Status")
        self._setup_status_tab()
        
        # Status bar at the bottom
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _setup_alerts_tab(self):
        # Controls frame
        controls_frame = ttk.Frame(self.alerts_frame)
        controls_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(controls_frame, text="Priority Filter:").pack(side=tk.LEFT, padx=5)
        self.priority_var = tk.StringVar(value="All")
        priority_combo = ttk.Combobox(controls_frame, textvariable=self.priority_var, 
                                      values=["All", "High", "Medium", "Low"], width=10)
        priority_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls_frame, text="Refresh", command=self._refresh_alerts).pack(side=tk.RIGHT, padx=5)
        
        # Alert table
        columns = ("Time", "Priority", "Source IP", "Destination IP", "Message", "SID")
        self.alert_tree = ttk.Treeview(self.alerts_frame, columns=columns, show="headings")
        
        # Configure column widths and headings
        self.alert_tree.column("Time", width=150)
        self.alert_tree.column("Priority", width=70)
        self.alert_tree.column("Source IP", width=120)
        self.alert_tree.column("Destination IP", width=120)
        self.alert_tree.column("Message", width=400)
        self.alert_tree.column("SID", width=80)
        
        for col in columns:
            self.alert_tree.heading(col, text=col)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.alerts_frame, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscroll=scrollbar.set)
        
        # Pack elements
        self.alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _setup_firewall_tab(self):
        # Controls frame
        controls_frame = ttk.Frame(self.firewall_frame)
        controls_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(controls_frame, text="Action Filter:").pack(side=tk.LEFT, padx=5)
        self.action_var = tk.StringVar(value="All")
        action_combo = ttk.Combobox(controls_frame, textvariable=self.action_var, 
                                   values=["All", "Allow", "Deny", "Log"], width=10)
        action_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls_frame, text="Refresh", command=self._refresh_firewall).pack(side=tk.RIGHT, padx=5)
        
        # Firewall rules table
        columns = ("ID", "Priority", "Action", "Protocol", "Source IP", "Destination IP", "Description")
        self.firewall_tree = ttk.Treeview(self.firewall_frame, columns=columns, show="headings")
        
        # Configure column widths
        self.firewall_tree.column("ID", width=80)
        self.firewall_tree.column("Priority", width=70)
        self.firewall_tree.column("Action", width=70)
        self.firewall_tree.column("Protocol", width=70)
        self.firewall_tree.column("Source IP", width=120)
        self.firewall_tree.column("Destination IP", width=120)
        self.firewall_tree.column("Description", width=400)
        
        for col in columns:
            self.firewall_tree.heading(col, text=col)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.firewall_frame, orient=tk.VERTICAL, command=self.firewall_tree.yview)
        self.firewall_tree.configure(yscroll=scrollbar.set)
        
        # Pack elements
        self.firewall_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _setup_status_tab(self):
        # System status information
        frame = ttk.LabelFrame(self.status_frame, text="System Status")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Status indicators
        self.snort_status = ttk.Label(frame, text="Snort IDS: Not running")
        self.snort_status.grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        
        self.firewall_status = ttk.Label(frame, text="Firewall: Not running")
        self.firewall_status.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        
        self.alert_count = ttk.Label(frame, text="Total Alerts: 0")
        self.alert_count.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        
        self.firewall_rules_count = ttk.Label(frame, text="Active Firewall Rules: 0")
        self.firewall_rules_count.grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(self.status_frame, text="Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.packets_processed = ttk.Label(stats_frame, text="Packets Processed: 0")
        self.packets_processed.grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        
        self.alerts_generated = ttk.Label(stats_frame, text="Alerts Generated: 0")
        self.alerts_generated.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        
        self.blocked_connections = ttk.Label(stats_frame, text="Blocked Connections: 0")
        self.blocked_connections.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
    
    def _refresh_alerts(self):
        # Clear existing data
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        
        # Get alerts from provider
        alerts = self.alert_provider()
        
        # Apply priority filter if not "All"
        priority_filter = self.priority_var.get()
        if priority_filter != "All":
            priority_map = {"High": [1, 2], "Medium": [3, 4], "Low": [5, 6, 7, 8, 9, 10]}
            filtered_alerts = [a for a in alerts if a.get("priority", 0) in priority_map.get(priority_filter, [])]
        else:
            filtered_alerts = alerts
        
        # Add to treeview
        for alert in filtered_alerts:
            values = (
                alert.get("timestamp", ""),
                alert.get("priority", ""),
                alert.get("src_ip", ""),
                alert.get("dst_ip", ""),
                alert.get("message", ""),
                alert.get("sid", "")
            )
            self.alert_tree.insert("", tk.END, values=values)
        
        self.status_bar.config(text=f"Alerts refreshed: {len(filtered_alerts)} alerts shown")
    
    def _refresh_firewall(self):
        # Clear existing data
        for item in self.firewall_tree.get_children():
            self.firewall_tree.delete(item)
        
        # Get firewall rules from provider
        rules = self.firewall_provider()
        
        # Apply action filter if not "All"
        action_filter = self.action_var.get()
        if action_filter != "All":
            filtered_rules = [r for r in rules if r.get("action", "").lower() == action_filter.lower()]
        else:
            filtered_rules = rules
        
        # Add to treeview
        for rule in filtered_rules:
            values = (
                rule.get("id", ""),
                rule.get("priority", ""),
                rule.get("action", ""),
                rule.get("protocol", ""),
                rule.get("source_ip", ""),
                rule.get("destination_ip", ""),
                rule.get("description", "")
            )
            self.firewall_tree.insert("", tk.END, values=values)
        
        self.status_bar.config(text=f"Firewall rules refreshed: {len(filtered_rules)} rules shown")
    
    def update_system_status(self, status_data):
        # Update status labels with current system information
        self.snort_status.config(text=f"Snort IDS: {status_data.get('snort_status', 'Unknown')}")
        self.firewall_status.config(text=f"Firewall: {status_data.get('firewall_status', 'Unknown')}")
        self.alert_count.config(text=f"Total Alerts: {status_data.get('alert_count', 0)}")
        self.firewall_rules_count.config(text=f"Active Firewall Rules: {status_data.get('firewall_rules_count', 0)}")
        
        # Update statistics
        self.packets_processed.config(text=f"Packets Processed: {status_data.get('packets_processed', 0)}")
        self.alerts_generated.config(text=f"Alerts Generated: {status_data.get('alerts_generated', 0)}")
        self.blocked_connections.config(text=f"Blocked Connections: {status_data.get('blocked_connections', 0)}")
    
    def _refresh_loop(self):
        while self.should_refresh:
            # Only refresh the currently visible tab
            current_tab = self.notebook.index(self.notebook.select())
            
            if current_tab == 0:  # Alerts tab
                self._refresh_alerts()
            elif current_tab == 1:  # Firewall tab
                self._refresh_firewall()
            
            # Sleep for the refresh interval
            time.sleep(self.refresh_interval)
    
    def stop(self):
        self.should_refresh = False
        if self.refresh_thread.is_alive():
            self.refresh_thread.join(timeout=1)


def launch_dashboard(alert_provider_func, firewall_provider_func):
    root = tk.Tk()
    dashboard = Dashboard(root, alert_provider_func, firewall_provider_func)
    
    def on_close():
        dashboard.stop()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()