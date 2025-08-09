import tkinter as tk
from tkinter import ttk, scrolledtext
import tkinter.font as tkFont
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.arch.windows import get_windows_if_list
import requests
import time
from collections import defaultdict
import ipaddress
import threading
import queue
from datetime import datetime
import json
import subprocess
import sys

class CyberFrame(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(bg='#0a0a0a', relief='flat', bd=2)

class AnimatedLabel(tk.Label):
    def __init__(self, parent, text="", delay=30, **kwargs):
        super().__init__(parent, **kwargs)
        self.original_text = text
        self.delay = delay
        self.typing_job = None
        if text:
            self.animate_typing()

    def animate_typing(self):
        if self.typing_job:
            self.after_cancel(self.typing_job)
        self.configure(text="")
        self.type_text(self.original_text, 0)

    def type_text(self, text, index):
        if index <= len(text):
            current = text[:index]
            cursor = '█' if index < len(text) else ''
            self.configure(text=current + cursor)
            self.typing_job = self.after(self.delay, lambda: self.type_text(text, index + 1))
        else:
            self.configure(text=text)

    def set_text(self, new_text, animate=True):
        self.original_text = new_text
        if animate:
            self.animate_typing()
        else:
            self.configure(text=new_text)

class InfoPopup(tk.Toplevel):
    def __init__(self, parent, title, info, colors, fonts):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=colors['bg'])
        self.geometry('400x200')

        self.transient(parent)
        self.grab_set()

        info_text = scrolledtext.ScrolledText(
            self,
            font=fonts['mono'],
            bg=colors['bg'],
            fg=colors['text'],
            relief='flat',
            height=8,
            width=40
        )
        info_text.pack(padx=10, pady=10, fill='both', expand=True)
        info_text.insert('1.0', info)
        info_text.configure(state='disabled')

        tk.Button(
            self,
            text="Close",
            command=self.destroy,
            font=fonts['mono'],
            bg=colors['accent'],
            fg='black'
        ).pack(pady=5)

class GTAMonitorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("v.11.0")
        self.root.configure(bg='#0a0a0a')
        self.root.geometry('1400x900')
        self.root.resizable(True, True)

        self.colors = {
            'bg': '#0a0a0a',
            'secondary_bg': '#1a1a1a',
            'accent': '#00ff41',
            'accent2': '#ff6b35',
            'text': '#00ff41',
            'text_secondary': '#888888',
            'warning': '#ff6b35',
            'border': '#333333',
            'critical': '#ff0040',
            'info': '#40a0ff'
        }

        self.CACHE_TIME = 3600
        self.ACTIVE_SESSIONS = {}
        self.LAST_SEEN = defaultdict(float)
        self.MIN_SESSION_GAP = 30  
        self.GTA_PORTS = {6672, 61455, 61456, 61457, 61458}

        self.PRIVATE_NETS = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),  
            ipaddress.ip_network('224.0.0.0/4'),     
            ipaddress.ip_network('255.255.255.255/32') 
        ]

        self.monitoring = False
        self.selected_interface = None
        self.packet_queue = queue.Queue()
        self.geo_queue = queue.Queue()
        self.processed_ips = set()
        self.session_players = {}

        self.packet_count = 0
        self.total_detected = 0
        self.start_time = 0

        self.setup_fonts()
        self.setup_gui()
        self.start_gui_updates()

    def setup_fonts(self):
        self.fonts = {
            'title': tkFont.Font(family='Consolas', size=18, weight='bold'),
            'header': tkFont.Font(family='Consolas', size=13, weight='bold'),
            'mono': tkFont.Font(family='Consolas', size=10),
            'status': tkFont.Font(family='Consolas', size=9),
            'small': tkFont.Font(family='Consolas', size=8)
        }

    def setup_gui(self):

        main_container = CyberFrame(self.root, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True, padx=10, pady=10)

        self.setup_title_section(main_container)

        self.setup_control_panel(main_container)

        self.setup_stats_panel(main_container)

        self.setup_player_panel(main_container)

        self.setup_log_display(main_container)

        self.setup_status_bar(main_container)

    def setup_title_section(self, parent):
        title_frame = CyberFrame(parent, bg=self.colors['bg'])
        title_frame.pack(fill='x', pady=(0, 10))

        self.title_label = AnimatedLabel(title_frame, 
                                        text="◤ 1y's GTA V UDP MONITOR ◤",
                                        font=self.fonts['title'],
                                        fg=self.colors['accent'],
                                        bg=self.colors['bg'],
                                        delay=50) 
        self.title_label.pack(side='left')

        version_label = tk.Label(title_frame,
                               text="v.11.0",
                               font=self.fonts['status'],
                               fg=self.colors['text_secondary'],
                               bg=self.colors['bg'])
        version_label.pack(side='right')

        separator = tk.Frame(parent, height=2, bg=self.colors['accent'])
        separator.pack(fill='x', pady=5)

    def setup_control_panel(self, parent):
        control_frame = CyberFrame(parent, bg=self.colors['secondary_bg'], relief='ridge', bd=1)
        control_frame.pack(fill='x', pady=(0, 10), padx=2)

        self.control_header = AnimatedLabel(control_frame,
                                          text="▶ CONTROL PANEL",
                                          font=self.fonts['header'],
                                          fg=self.colors['accent'],
                                          bg=self.colors['secondary_bg'],
                                          delay=20)
        self.control_header.pack(anchor='w', padx=10, pady=(5, 0))

        controls_container = tk.Frame(control_frame, bg=self.colors['secondary_bg'])
        controls_container.pack(fill='x', padx=10, pady=5)

        interface_frame = tk.Frame(controls_container, bg=self.colors['secondary_bg'])
        interface_frame.pack(side='left', fill='x', expand=True)

        tk.Label(interface_frame,
                text="INTERFACE:",
                font=self.fonts['mono'],
                fg=self.colors['text'],
                bg=self.colors['secondary_bg']).pack(side='left')

        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(interface_frame,
                                          textvariable=self.interface_var,
                                          font=self.fonts['mono'],
                                          state='readonly',
                                          width=40)
        self.interface_combo.pack(side='left', padx=(10, 0))

        self.load_interfaces()

        button_frame = tk.Frame(controls_container, bg=self.colors['secondary_bg'])
        button_frame.pack(side='right', padx=(20, 0))

        self.start_button = tk.Button(button_frame,
                                    text="◆ START",
                                    font=self.fonts['mono'],
                                    bg=self.colors['accent'],
                                    fg='black',
                                    relief='flat',
                                    padx=20,
                                    command=self.toggle_monitoring)
        self.start_button.pack(side='left', padx=5)

        self.clear_button = tk.Button(button_frame,
                                    text="◇ CLEAR",
                                    font=self.fonts['mono'],
                                    bg=self.colors['warning'],
                                    fg='black',
                                    relief='flat',
                                    padx=20,
                                    command=self.clear_logs)
        self.clear_button.pack(side='left', padx=5)

        self.restart_button = tk.Button(button_frame,
                                      text="⟲ RESTART",
                                      font=self.fonts['mono'],
                                      bg=self.colors['critical'],
                                      fg='white',
                                      relief='flat',
                                      padx=20,
                                      command=self.restart_program)
        self.restart_button.pack(side='left', padx=5)

    def setup_stats_panel(self, parent):
        stats_frame = CyberFrame(parent, bg=self.colors['secondary_bg'], relief='ridge', bd=1)
        stats_frame.pack(fill='x', pady=(0, 10), padx=2)

        self.stats_header = AnimatedLabel(stats_frame,
                                        text="▶ NETWORK STATISTICS",
                                        font=self.fonts['header'],
                                        fg=self.colors['accent'],
                                        bg=self.colors['secondary_bg'],
                                        delay=20)
        self.stats_header.pack(anchor='w', padx=10, pady=(5, 0))

        stats_container = tk.Frame(stats_frame, bg=self.colors['secondary_bg'])
        stats_container.pack(fill='x', padx=10, pady=5)

        self.stats = {}
        stat_items = [
            ('ACTIVE_PLAYERS', '0', self.colors['accent']),
            ('SESSION_TOTAL', '0', self.colors['info']),
            ('PACKETS_CAPTURED', '0', self.colors['text']),
            ('UPTIME', '00:00:00', self.colors['warning'])
        ]

        for label, initial_value, color in stat_items:
            frame = tk.Frame(stats_container, bg=self.colors['secondary_bg'])
            frame.pack(side='left', fill='x', expand=True)

            tk.Label(frame,
                    text=f"{label}:",
                    font=self.fonts['status'],
                    fg=self.colors['text_secondary'],
                    bg=self.colors['secondary_bg']).pack()

            self.stats[label] = tk.Label(frame,
                                       text=initial_value,
                                       font=self.fonts['mono'],
                                       fg=color,
                                       bg=self.colors['secondary_bg'])
            self.stats[label].pack()

    def setup_player_panel(self, parent):
        player_frame = CyberFrame(parent, bg=self.colors['secondary_bg'], relief='ridge', bd=1)
        player_frame.pack(fill='x', pady=(0, 10), padx=2, ipady=5)

        self.player_header = AnimatedLabel(player_frame,
                                         text="▶ ACTIVE PLAYERS IN SESSION",
                                         font=self.fonts['header'],
                                         fg=self.colors['accent'],
                                         bg=self.colors['secondary_bg'],
                                         delay=20)
        self.player_header.pack(anchor='w', padx=10, pady=(5, 0))

        player_container = tk.Frame(player_frame, bg=self.colors['secondary_bg'], height=120)
        player_container.pack(fill='x', padx=10, pady=5)
        player_container.pack_propagate(False)

        self.player_canvas = tk.Canvas(player_container, 
                                     bg=self.colors['bg'],
                                     height=100,
                                     highlightthickness=0)
        scrollbar = ttk.Scrollbar(player_container, orient="horizontal", command=self.player_canvas.xview)
        self.scrollable_frame = tk.Frame(self.player_canvas, bg=self.colors['bg'])

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.player_canvas.configure(scrollregion=self.player_canvas.bbox("all"))
        )

        self.player_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.player_canvas.configure(xscrollcommand=scrollbar.set)

        self.player_canvas.pack(side="top", fill="both", expand=True)
        scrollbar.pack(side="bottom", fill="x")

    def setup_log_display(self, parent):
        log_frame = CyberFrame(parent, bg=self.colors['secondary_bg'], relief='ridge', bd=1)
        log_frame.pack(fill='both', expand=True, padx=2)

        header_frame = tk.Frame(log_frame, bg=self.colors['secondary_bg'])
        header_frame.pack(fill='x', padx=10, pady=(5, 0))

        self.log_header = AnimatedLabel(header_frame,
                                      text="▶ DETECTION LOG",
                                      font=self.fonts['header'],
                                      fg=self.colors['accent'],
                                      bg=self.colors['secondary_bg'],
                                      delay=20)
        self.log_header.pack(side='left')

        controls_frame = tk.Frame(header_frame, bg=self.colors['secondary_bg'])
        controls_frame.pack(side='right')

        self.auto_scroll_var = tk.BooleanVar(value=True)
        auto_scroll_cb = tk.Checkbutton(controls_frame,
                                       text="AUTO-SCROLL",
                                       variable=self.auto_scroll_var,
                                       font=self.fonts['small'],
                                       fg=self.colors['text'],
                                       bg=self.colors['secondary_bg'],
                                       selectcolor=self.colors['bg'])
        auto_scroll_cb.pack(side='right', padx=5)

        self.show_geo_var = tk.BooleanVar(value=True)
        geo_cb = tk.Checkbutton(controls_frame,
                               text="SHOW GEO",
                               variable=self.show_geo_var,
                               font=self.fonts['small'],
                               fg=self.colors['text'],
                               bg=self.colors['secondary_bg'],
                               selectcolor=self.colors['bg'])
        geo_cb.pack(side='right', padx=5)

        log_container = tk.Frame(log_frame, bg=self.colors['secondary_bg'])
        log_container.pack(fill='both', expand=True, padx=10, pady=(0, 5))

        self.log_text = scrolledtext.ScrolledText(log_container,
                                                font=self.fonts['mono'],
                                                bg=self.colors['bg'],
                                                fg=self.colors['text'],
                                                insertbackground=self.colors['accent'],
                                                selectbackground=self.colors['accent'],
                                                selectforeground='black',
                                                relief='flat',
                                                bd=5,
                                                wrap='word')
        self.log_text.pack(fill='both', expand=True)

        self.add_animated_log("◢ GTA V UDP MONITOR ENHANCED INITIALIZED ◣", self.colors['accent'])
        self.add_animated_log("Enhanced detection algorithm loaded...", self.colors['text_secondary'])
        self.add_animated_log("Monitoring ports: 6672, 61455-61458", self.colors['text_secondary'])
        self.add_animated_log("Ready for session detection...", self.colors['text_secondary'])
        self.add_log("═" * 60, self.colors['border'])

    def setup_status_bar(self, parent):
        status_frame = tk.Frame(parent, bg=self.colors['border'], height=25)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)

        self.status_label = AnimatedLabel(status_frame,
                                        text="● IDLE - Select interface and click START",
                                        font=self.fonts['status'],
                                        fg=self.colors['warning'],
                                        bg=self.colors['border'],
                                        delay=20)
        self.status_label.pack(side='left', padx=10, pady=2)

        self.time_label = tk.Label(status_frame,
                                 text="",
                                 font=self.fonts['status'],
                                 fg=self.colors['text_secondary'],
                                 bg=self.colors['border'])
        self.time_label.pack(side='right', padx=10, pady=2)

    def load_interfaces(self):
        try:
            ifaces = get_windows_if_list()
            interface_list = []
            for iface in ifaces:
                name = iface['name']
                desc = iface['description'][:50] + "..." if len(iface['description']) > 50 else iface['description']
                interface_list.append(f"{name} - {desc}")

            self.interface_combo['values'] = interface_list
            self.interface_data = ifaces
            if interface_list:
                self.interface_combo.current(0)
        except Exception as e:
            self.add_log(f"Error loading interfaces: {e}", self.colors['warning'])

    def add_log(self, message, color=None):
        if color is None:
            color = self.colors['text']

        timestamp = datetime.now().strftime("[%H:%M:%S]")
        full_message = f"{timestamp} {message}\n"

        self.log_text.insert('end', full_message)

        start_line = self.log_text.index('end-2c linestart')
        end_line = self.log_text.index('end-1c')
        tag_name = f"color_{id(message)}"
        self.log_text.tag_add(tag_name, start_line, end_line)
        self.log_text.tag_config(tag_name, foreground=color)

        if self.auto_scroll_var.get():
            self.log_text.see('end')

    def add_animated_log(self, message, color=None, delay=30):
        """Add log entry with typing animation"""
        if color is None:
            color = self.colors['text']

        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.animate_log_text(f"{timestamp} {message}", color, delay)

    def animate_log_text(self, full_message, color, delay):
        """Animate text appearing character by character in log"""
        def type_char(text, index):
            if index <= len(text):
                current_text = text[:index] + ('█' if index < len(text) else '')

                try:
                    last_line_start = self.log_text.index('end-1c linestart')
                    last_line_end = self.log_text.index('end-1c')
                    self.log_text.delete(last_line_start, last_line_end)
                    self.log_text.insert('end', current_text)
                except:
                    self.log_text.insert('end', current_text)

                start_line = self.log_text.index('end-1c linestart')
                end_line = self.log_text.index('end-1c')
                tag_name = f"animated_{time.time()}"
                self.log_text.tag_add(tag_name, start_line, end_line)
                self.log_text.tag_config(tag_name, foreground=color)

                if self.auto_scroll_var.get():
                    self.log_text.see('end')

                if index < len(text):
                    self.root.after(delay, lambda: type_char(text, index + 1))
                else:

                    self.log_text.insert('end', '\n')
                    if self.auto_scroll_var.get():
                        self.log_text.see('end')

        self.log_text.insert('end', '\n')
        type_char(full_message, 0)

    def clear_logs(self):
        self.log_text.delete(1.0, 'end')
        self.add_animated_log("◢ LOG CLEARED ◣", self.colors['warning'])

    def restart_program(self):
        """Restart the entire program"""
        self.add_animated_log("◢ RESTARTING PROGRAM ◣", self.colors['critical'])
        if self.monitoring:
            self.stop_monitoring()

        self.root.after(1000, lambda: (
            self.root.destroy(),
            subprocess.Popen([sys.executable, __file__])
        ))

    def toggle_monitoring(self):
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        if not self.interface_var.get():
            self.add_animated_log("ERROR: No interface selected!", self.colors['warning'])
            return

        self.monitoring = True
        self.start_time = time.time()
        self.packet_count = 0
        self.total_detected = 0
        self.processed_ips.clear()
        self.session_players.clear()

        self.start_button.configure(text="◆ STOP", bg=self.colors['warning'])
        self.status_label.set_text("● MONITORING - Scanning for GTA sessions...", True)

        selected_idx = self.interface_combo.current()
        if selected_idx >= 0:
            self.selected_interface = self.interface_data[selected_idx]['name']

        self.add_animated_log(f"Initializing capture on: {self.selected_interface}", self.colors['accent'])
        self.add_animated_log("Starting enhanced packet analysis...", self.colors['info'])

        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        self.capture_thread = threading.Thread(target=self.packet_capture_worker, daemon=True)
        self.capture_thread.start()

        self.geo_thread = threading.Thread(target=self.geolocation_worker, daemon=True)
        self.geo_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.start_button.configure(text="◆ START", bg=self.colors['accent'])
        self.status_label.set_text("● STOPPED - Monitoring halted", True)
        self.add_animated_log("Monitoring session ended", self.colors['warning'])

    def packet_capture_worker(self):
        try:
            conf.use_pcap = True
            conf.iface = self.selected_interface
            self.add_animated_log("Packet capture engine started", self.colors['info'])
            sniff(filter="udp", prn=self.packet_handler, store=0, stop_filter=lambda x: not self.monitoring)
        except Exception as e:
            self.packet_queue.put(('error', f"Capture error: {e}"))

    def geolocation_worker(self):
        """Dedicated thread for handling geolocation requests"""
        while self.monitoring:
            try:
                ip = self.geo_queue.get(timeout=1)
                if ip and self.monitoring:
                    geo_info = self.geolocate_ip(ip)
                    if geo_info != "Geolocation failed":
                        self.packet_queue.put(('geo_result', {'ip': ip, 'geo': geo_info}))
            except queue.Empty:
                continue
            except Exception as e:
                continue

    def is_private_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in self.PRIVATE_NETS)
        except:
            return True  

    def is_valid_gta_traffic(self, pkt):
        """Enhanced GTA traffic detection"""
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return False

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

        has_gta_port = src_port in self.GTA_PORTS or dst_port in self.GTA_PORTS

        payload_size = len(pkt[UDP].payload)

        valid_payload = 20 <= payload_size <= 1200

        is_public = not self.is_private_ip(src_ip)

        return has_gta_port and valid_payload and is_public

    def geolocate_ip(self, ip):
        if ip in self.ACTIVE_SESSIONS:
            cached_data = self.ACTIVE_SESSIONS[ip]
            if time.time() - cached_data.get('timestamp', 0) < self.CACHE_TIME:
                return cached_data.get('geo', 'Unknown')

        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org", 
                                  timeout=5)
            data = response.json()

            if data.get('status') == 'success':
                city = data.get('city', 'Unknown')
                region = data.get('regionName', 'Unknown')
                country = data.get('country', 'Unknown')
                isp = data.get('isp', data.get('org', 'Unknown ISP'))

                geo_info = f"{city}, {region}, {country} ({isp})"

                self.ACTIVE_SESSIONS[ip] = {
                    'geo': geo_info,
                    'timestamp': time.time(),
                    'first_seen': time.time()
                }

                return geo_info
        except Exception as e:
            pass

        return "Geolocation failed"

    def should_process_ip(self, ip):
        """Enhanced IP processing logic"""
        now = time.time()

        if ip in self.LAST_SEEN:
            time_diff = now - self.LAST_SEEN[ip]
            if time_diff < self.MIN_SESSION_GAP:
                return False

        self.LAST_SEEN[ip] = now
        return True

    def packet_handler(self, pkt):
        if not self.monitoring:
            return

        self.packet_count += 1

        if self.is_valid_gta_traffic(pkt):
            src_ip = pkt[IP].src
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            if self.should_process_ip(src_ip) and src_ip not in self.processed_ips:
                self.processed_ips.add(src_ip)

                player_data = {
                    'ip': src_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'timestamp': time.time(),
                    'payload_size': len(pkt[UDP].payload)
                }

                self.packet_queue.put(('player', player_data))

                self.geo_queue.put(src_ip)

    def update_player_display(self):
        """Update the visual player list"""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        active_count = 0
        current_time = time.time()

        for ip, data in self.session_players.items():
            time_since_last_seen = current_time - data['last_seen']
            is_active = time_since_last_seen < 300  

            player_frame = tk.Frame(self.scrollable_frame, 
                                  bg=self.colors['secondary_bg'],
                                  relief='ridge', bd=1)
            player_frame.pack(side='left', padx=5, pady=2, fill='y')

            ip_button = tk.Button(
                player_frame,
                text=ip,
                font=self.fonts['small'],
                fg=self.colors['accent'],
                bg=self.colors['secondary_bg'],
                bd=0,
                cursor='hand2',
                command=lambda i=ip, d=data: self.show_player_info(i, d)
            )
            ip_button.pack(padx=5, pady=2)

            if 'geo' in data and data['geo'] != 'Geolocation failed':
                geo_parts = data['geo'].split(',')
                location = geo_parts[0] if geo_parts else 'Unknown'
                geo_label = tk.Label(
                    player_frame,
                    text=location,
                    font=self.fonts['small'],
                    fg=self.colors['text_secondary'],
                    bg=self.colors['secondary_bg']
                )
                geo_label.pack(padx=5)

            status_text = "● ACTIVE" if is_active else "○ LEFT"
            status_color = self.colors['accent'] if is_active else self.colors['warning']
            status_label = tk.Label(
                player_frame,
                text=status_text,
                font=self.fonts['small'],
                fg=status_color,
                bg=self.colors['secondary_bg']
            )
            status_label.pack()

            if is_active:
                active_count += 1

        self.player_canvas.configure(scrollregion=self.player_canvas.bbox("all"))
        return active_count

    def show_player_info(self, ip, data):
        """Show detailed player information popup"""
        current_time = time.time()
        time_since_last_seen = current_time - data['last_seen']

        info_text = f"""IP Address: {ip}
Last Seen: {time.strftime('%H:%M:%S', time.localtime(data['last_seen']))} ({int(time_since_last_seen)}s ago)
First Seen: {time.strftime('%H:%M:%S', time.localtime(data.get('first_seen', current_time)))}
Status: {'Active' if time_since_last_seen < 300 else 'Left'}
Ports: {data.get('src_port', 'N/A')} → {data.get('dst_port', 'N/A')}
Payload Size: {data.get('payload_size', 'N/A')}b
Location: {data.get('geo', 'Unknown')}"""

        popup = InfoPopup(self.root, f"Player Info - {ip}", info_text, self.colors, self.fonts)
        popup.focus_set()

    def run(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            if self.monitoring:
                self.stop_monitoring()

    def start_gui_updates(self):
        """Start periodic GUI updates"""
        def update():
            if self.monitoring:

                uptime = time.time() - self.start_time
                hours = int(uptime // 3600)
                minutes = int((uptime % 3600) // 60)
                seconds = int(uptime % 60)
                self.stats['UPTIME'].configure(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")

                self.stats['PACKETS_CAPTURED'].configure(text=str(self.packet_count))

                self.stats['SESSION_TOTAL'].configure(text=str(len(self.session_players)))

                while not self.packet_queue.empty():
                    msg_type, data = self.packet_queue.get()

                    if msg_type == 'player':
                        ip = data['ip']
                        if ip not in self.session_players:
                            self.total_detected += 1
                            self.add_log(f"New player detected: {ip}", self.colors['accent'])

                        self.session_players[ip] = {
                            'first_seen': self.session_players.get(ip, {}).get('first_seen', time.time()),
                            'last_seen': time.time(),
                            'src_port': data['src_port'],
                            'dst_port': data['dst_port'],
                            'payload_size': data['payload_size']
                        }

                    elif msg_type == 'geo_result':
                        ip = data['ip']
                        if ip in self.session_players:
                            self.session_players[ip]['geo'] = data['geo']
                            if self.show_geo_var.get():
                                self.add_log(f"Location for {ip}: {data['geo']}", self.colors['info'])

                    elif msg_type == 'error':
                        self.add_log(data, self.colors['warning'])

                active_count = self.update_player_display()
                self.stats['ACTIVE_PLAYERS'].configure(text=str(active_count))

                current_time = time.strftime("%H:%M:%S")
                self.time_label.configure(text=current_time)

            self.root.after(1000, update)

        update()

if __name__ == "__main__":
    try:
        app = GTAMonitorGUI()
        app.run()
    except PermissionError:
        print("ERROR: Run as Administrator!")
    except Exception as e:
        print(f"Error: {e}")
