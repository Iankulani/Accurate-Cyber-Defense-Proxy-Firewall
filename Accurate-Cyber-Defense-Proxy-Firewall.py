import sys
import socket
import threading
import time
import json
import re
import os
import ssl
import select
import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import queue
import ping3
import subprocess
import requests
from urllib.parse import urlparse
import dns.resolver
import io
import csv
from tkinter import font as tkfont
import platform
import psutil
import netifaces
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import ipaddress
import whois
import random
import sqlite3
from PIL import Image, ImageTk

# Constants
CONFIG_FILE = 'accurate_config.json'
DB_FILE = 'accurate_data.db'
LOG_FILE = 'accurate.log'
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
BACKUP_COUNT = 3

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('CyberShield')

class AccurateCyberDefenseProxyFirewall:
    def __init__(self):
        # Initialize configuration
        self.config = {
            'proxy': {
                'http_port': 8080,
                'https_port': 8443,
                'dns_port': 5353,
                'enabled': True
            },
            'monitoring': {
                'active_ips': [],
                'alert_threshold': 100,  # requests per minute
                'blocked_ips': []
            },
            'telegram': {
                'token': '',
                'chat_id': '',
                'enabled': False
            },
            'ui': {
                'theme': 'purple_black',
                'font_size': 10
            }
        }
        
        # Load configuration
        self.load_config()
        
        # Initialize data structures
        self.traffic_data = {}  # {ip: {timestamp: data}}
        self.threat_data = {}  # {ip: threat_info}
        self.connections = {}
        self.running = False
        self.proxy_threads = []
        self.monitoring_thread = None
        self.gui_update_queue = queue.Queue()
        
        # Initialize database
        self.init_db()
        
        # GUI components
        self.root = None
        self.tabs = None
        self.status_bar = None
        self.log_text = None
        self.traffic_chart_frame = None
        self.threat_chart_frame = None
        self.ip_listbox = None
        self.command_entry = None
        self.command_history = []
        self.history_index = -1
        
        # Start the GUI
        self.start_gui()
        
        # Start the proxy
        self.start_proxy()
        
        # Start monitoring
        self.start_monitoring()
    
    # Configuration management
    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge loaded config with default config
                    for section in self.config:
                        if section in loaded_config:
                            self.config[section].update(loaded_config[section])
            self.save_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
    
    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    # Database management
    def init_db(self):
        try:
            self.db_conn = sqlite3.connect(DB_FILE)
            cursor = self.db_conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    timestamp DATETIME,
                    protocol TEXT,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    domain TEXT,
                    url TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    timestamp DATETIME,
                    threat_type TEXT,
                    severity INTEGER,
                    description TEXT,
                    action_taken TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    timestamp DATETIME,
                    reason TEXT,
                    duration_minutes INTEGER
                )
            ''')
            
            self.db_conn.commit()
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
    
    def save_traffic_data(self, ip, protocol, bytes_sent, bytes_received, domain=None, url=None):
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT INTO traffic_data (ip, timestamp, protocol, bytes_sent, bytes_received, domain, url)
                VALUES (?, datetime('now'), ?, ?, ?, ?, ?)
            ''', (ip, protocol, bytes_sent, bytes_received, domain, url))
            self.db_conn.commit()
        except Exception as e:
            logger.error(f"Error saving traffic data: {e}")
    
    def save_threat_data(self, ip, threat_type, severity, description, action_taken):
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT INTO threat_data (ip, timestamp, threat_type, severity, description, action_taken)
                VALUES (?, datetime('now'), ?, ?, ?, ?)
            ''', (ip, threat_type, severity, description, action_taken))
            self.db_conn.commit()
        except Exception as e:
            logger.error(f"Error saving threat data: {e}")
    
    # Proxy functionality
    def start_proxy(self):
        if not self.config['proxy']['enabled']:
            return
            
        self.running = True
        
        # Start HTTP proxy
        http_thread = threading.Thread(target=self.run_http_proxy, daemon=True)
        http_thread.start()
        self.proxy_threads.append(http_thread)
        
        # Start HTTPS proxy
        https_thread = threading.Thread(target=self.run_https_proxy, daemon=True)
        https_thread.start()
        self.proxy_threads.append(https_thread)
        
        # Start DNS proxy
        dns_thread = threading.Thread(target=self.run_dns_proxy, daemon=True)
        dns_thread.start()
        self.proxy_threads.append(dns_thread)
        
        logger.info("Proxy services started")
    
    def stop_proxy(self):
        self.running = False
        logger.info("Proxy services stopping...")
    
    def run_http_proxy(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', self.config['proxy']['http_port']))
                server_socket.listen(5)
                logger.info(f"HTTP proxy listening on port {self.config['proxy']['http_port']}")
                
                while self.running:
                    try:
                        client_socket, client_addr = server_socket.accept()
                        threading.Thread(
                            target=self.handle_http_connection,
                            args=(client_socket, client_addr),
                            daemon=True
                        ).start()
                    except Exception as e:
                        logger.error(f"HTTP proxy error: {e}")
        except Exception as e:
            logger.error(f"HTTP proxy failed: {e}")
    
    def handle_http_connection(self, client_socket, client_addr):
        try:
            client_ip = client_addr[0]
            request = client_socket.recv(4096)
            
            if not request:
                return
                
            # Parse HTTP request
            first_line = request.split(b'\r\n')[0]
            method, url, version = first_line.decode().split()
            
            # Extract domain and path
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Check if IP is blocked
            if client_ip in self.config['monitoring']['blocked_ips']:
                response = b"HTTP/1.1 403 Forbidden\r\n\r\nYour IP has been blocked by CyberShield Proxy Firewall"
                client_socket.sendall(response)
                client_socket.close()
                self.save_threat_data(client_ip, "Blocked IP", 3, "Attempted access from blocked IP", "Blocked")
                return
            
            # Forward request to destination
            if not domain:
                domain = parsed_url.path.split('/')[0]
                path = '/' + '/'.join(parsed_url.path.split('/')[1:])
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as remote_socket:
                    remote_socket.connect((domain, 80))
                    remote_socket.sendall(request)
                    
                    response = b''
                    while True:
                        data = remote_socket.recv(4096)
                        if not data:
                            break
                        response += data
                    
                    # Send response back to client
                    client_socket.sendall(response)
                    
                    # Log traffic
                    bytes_sent = len(request)
                    bytes_received = len(response)
                    self.log_traffic(client_ip, 'HTTP', bytes_sent, bytes_received, domain, url)
                    
                    # Check for threats
                    self.analyze_traffic(client_ip, domain, url, response)
            except Exception as e:
                logger.error(f"HTTP forwarding error: {e}")
                error_response = b"HTTP/1.1 502 Bad Gateway\r\n\r\nCyberShield Proxy Error"
                client_socket.sendall(error_response)
        except Exception as e:
            logger.error(f"HTTP connection handling error: {e}")
        finally:
            client_socket.close()
    
    def run_https_proxy(self):
        try:
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')  # These should be generated
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', self.config['proxy']['https_port']))
                server_socket.listen(5)
                logger.info(f"HTTPS proxy listening on port {self.config['proxy']['https_port']}")
                
                while self.running:
                    try:
                        client_socket, client_addr = server_socket.accept()
                        ssl_socket = context.wrap_socket(client_socket, server_side=True)
                        threading.Thread(
                            target=self.handle_https_connection,
                            args=(ssl_socket, client_addr),
                            daemon=True
                        ).start()
                    except Exception as e:
                        logger.error(f"HTTPS proxy error: {e}")
        except Exception as e:
            logger.error(f"HTTPS proxy failed: {e}")
    
    def handle_https_connection(self, ssl_socket, client_addr):
        try:
            client_ip = client_addr[0]
            
            # HTTPS proxy typically handles CONNECT method for tunneling
            request = ssl_socket.recv(4096)
            
            if not request:
                return
                
            first_line = request.split(b'\r\n')[0]
            parts = first_line.decode().split()
            
            if len(parts) < 2:
                return
                
            method, url = parts[0], parts[1]
            
            if method.upper() == 'CONNECT':
                # Extract domain and port
                domain_port = url.split(':')
                domain = domain_port[0]
                port = int(domain_port[1]) if len(domain_port) > 1 else 443
                
                # Check if IP is blocked
                if client_ip in self.config['monitoring']['blocked_ips']:
                    response = b"HTTP/1.1 403 Forbidden\r\n\r\nYour IP has been blocked by CyberShield Proxy Firewall"
                    ssl_socket.sendall(response)
                    ssl_socket.close()
                    self.save_threat_data(client_ip, "Blocked IP", 3, "Attempted HTTPS access from blocked IP", "Blocked")
                    return
                
                # Establish tunnel
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as remote_socket:
                        remote_socket.connect((domain, port))
                        ssl_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        
                        # Monitor tunnel traffic
                        self.monitor_tunnel(ssl_socket, remote_socket, client_ip, domain)
                except Exception as e:
                    logger.error(f"HTTPS tunneling error: {e}")
                    ssl_socket.close()
        except Exception as e:
            logger.error(f"HTTPS connection handling error: {e}")
            ssl_socket.close()
    
    def monitor_tunnel(self, client_socket, remote_socket, client_ip, domain):
        sockets = [client_socket, remote_socket]
        bytes_sent = 0
        bytes_received = 0
        
        try:
            while self.running:
                readable, _, _ = select.select(sockets, [], [], 1)
                
                for sock in readable:
                    data = sock.recv(4096)
                    if not data:
                        return
                        
                    if sock is client_socket:
                        remote_socket.sendall(data)
                        bytes_sent += len(data)
                    else:
                        client_socket.sendall(data)
                        bytes_received += len(data)
        except Exception as e:
            logger.error(f"Tunnel monitoring error: {e}")
        finally:
            # Log traffic
            self.log_traffic(client_ip, 'HTTPS', bytes_sent, bytes_received, domain)
            
            # Close sockets
            client_socket.close()
            remote_socket.close()
    
    def run_dns_proxy(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
                server_socket.bind(('0.0.0.0', self.config['proxy']['dns_port']))
                logger.info(f"DNS proxy listening on port {self.config['proxy']['dns_port']}")
                
                while self.running:
                    try:
                        data, client_addr = server_socket.recvfrom(512)
                        threading.Thread(
                            target=self.handle_dns_request,
                            args=(server_socket, data, client_addr),
                            daemon=True
                        ).start()
                    except Exception as e:
                        logger.error(f"DNS proxy error: {e}")
        except Exception as e:
            logger.error(f"DNS proxy failed: {e}")
    
    def handle_dns_request(self, server_socket, data, client_addr):
        try:
            client_ip = client_addr[0]
            
            # Check if IP is blocked
            if client_ip in self.config['monitoring']['blocked_ips']:
                return  # Silently drop DNS requests from blocked IPs
            
            # Forward DNS request to upstream server (Google DNS)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
                upstream_socket.sendto(data, ('8.8.8.8', 53))
                response, _ = upstream_socket.recvfrom(512)
                
                # Send response back to client
                server_socket.sendto(response, client_addr)
                
                # Log DNS traffic
                self.log_traffic(client_ip, 'DNS', len(data), len(response))
                
                # Analyze DNS request for threats
                self.analyze_dns(data, client_ip)
        except Exception as e:
            logger.error(f"DNS request handling error: {e}")
    
    # Traffic and threat analysis
    def log_traffic(self, ip, protocol, bytes_sent, bytes_received, domain=None, url=None):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if ip not in self.traffic_data:
            self.traffic_data[ip] = {}
        
        if timestamp not in self.traffic_data[ip]:
            self.traffic_data[ip][timestamp] = {
                'protocol': protocol,
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'domain': domain,
                'url': url
            }
        else:
            self.traffic_data[ip][timestamp]['bytes_sent'] += bytes_sent
            self.traffic_data[ip][timestamp]['bytes_received'] += bytes_received
        
        # Save to database
        self.save_traffic_data(ip, protocol, bytes_sent, bytes_received, domain, url)
        
        # Update GUI if needed
        self.gui_update_queue.put(('traffic', ip))
    
    def analyze_traffic(self, ip, domain=None, url=None, response=None):
        # Check for excessive requests
        request_count = self.count_requests(ip)
        if request_count > self.config['monitoring']['alert_threshold']:
            threat_type = "Excessive Requests"
            description = f"IP {ip} made {request_count} requests in the last minute (threshold: {self.config['monitoring']['alert_threshold']})"
            self.handle_threat(ip, threat_type, 2, description)
        
        # Check for known malicious domains
        if domain and self.is_malicious_domain(domain):
            threat_type = "Malicious Domain"
            description = f"Access to known malicious domain: {domain}"
            self.handle_threat(ip, threat_type, 3, description, "Blocked")
            self.block_ip(ip, f"Access to malicious domain: {domain}")
        
        # Check response for malicious content
        if response and self.contains_malicious_content(response):
            threat_type = "Malicious Content"
            description = f"Response from {domain or ip} contains malicious content"
            self.handle_threat(ip, threat_type, 3, description, "Blocked")
            self.block_ip(ip, f"Malicious content from {domain or ip}")
    
    def analyze_dns(self, dns_data, client_ip):
        try:
            # Simple DNS analysis - extract query name
            query_name = dns_data[12:].split(b'\x00', 1)[0].decode('idna')
            
            # Check for known malicious domains
            if self.is_malicious_domain(query_name):
                threat_type = "Malicious DNS Query"
                description = f"DNS query for known malicious domain: {query_name}"
                self.handle_threat(client_ip, threat_type, 2, description)
        except Exception as e:
            logger.error(f"DNS analysis error: {e}")
    
    def count_requests(self, ip):
        now = datetime.datetime.now()
        one_minute_ago = now - datetime.timedelta(minutes=1)
        count = 0
        
        for timestamp_str in self.traffic_data.get(ip, {}):
            timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            if timestamp >= one_minute_ago:
                count += 1
                
        return count
    
    def is_malicious_domain(self, domain):
        # In a real implementation, this would check against a threat intelligence feed
        malicious_domains = [
            'malicious.com',
            'evil.org',
            'phishing.net',
            'malware.example'
        ]
        
        return domain.lower() in malicious_domains
    
    def contains_malicious_content(self, response):
        # Simple check for common malicious patterns
        malicious_patterns = [
            b'<script>evil_script()</script>',
            b'eval(',
            b'document.cookie',
            b'<iframe src="malicious"',
            b'%3Cscript%3E'  # URL encoded script tag
        ]
        
        return any(pattern in response for pattern in malicious_patterns)
    
    def handle_threat(self, ip, threat_type, severity, description, action_taken="Logged"):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if ip not in self.threat_data:
            self.threat_data[ip] = []
        
        threat_info = {
            'timestamp': timestamp,
            'type': threat_type,
            'severity': severity,
            'description': description,
            'action': action_taken
        }
        
        self.threat_data[ip].append(threat_info)
        
        # Save to database
        self.save_threat_data(ip, threat_type, severity, description, action_taken)
        
        # Send Telegram alert if enabled
        if self.config['telegram']['enabled'] and self.config['telegram']['token'] and self.config['telegram']['chat_id']:
            message = f"🚨 CyberShield Threat Alert 🚨\n\nIP: {ip}\nType: {threat_type}\nSeverity: {severity}\nDescription: {description}\nAction: {action_taken}"
            self.send_telegram_alert(message)
        
        # Update GUI
        self.gui_update_queue.put(('threat', ip))
    
    def block_ip(self, ip, reason, duration_minutes=60):
        if ip not in self.config['monitoring']['blocked_ips']:
            self.config['monitoring']['blocked_ips'].append(ip)
            self.save_config()
            
            # Log the block
            self.handle_threat(ip, "IP Blocked", 3, reason, f"Blocked for {duration_minutes} minutes")
            
            # Schedule unblock
            threading.Timer(duration_minutes * 60, self.unblock_ip, args=[ip]).start()
    
    def unblock_ip(self, ip):
        if ip in self.config['monitoring']['blocked_ips']:
            self.config['monitoring']['blocked_ips'].remove(ip)
            self.save_config()
            self.handle_threat(ip, "IP Unblocked", 1, "Block duration expired", "Unblocked")
    
    # Monitoring functionality
    def start_monitoring(self):
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
            
        self.monitoring_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitoring_thread.start()
        logger.info("Network monitoring started")
    
    def stop_monitoring(self):
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
            logger.info("Network monitoring stopped")
    
    def monitor_network(self):
        while self.running:
            try:
                # Check active connections
                self.check_active_connections()
                
                # Analyze traffic patterns
                self.analyze_traffic_patterns()
                
                # Check for new threats
                self.check_external_threat_feeds()
                
                # Sleep for a while
                time.sleep(30)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(10)
    
    def check_active_connections(self):
        try:
            # Get active connections using psutil
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    
                    if ip not in self.connections:
                        self.connections[ip] = {
                            'first_seen': datetime.datetime.now(),
                            'ports': set(),
                            'last_seen': datetime.datetime.now()
                        }
                    
                    self.connections[ip]['ports'].add(port)
                    self.connections[ip]['last_seen'] = datetime.datetime.now()
                    
                    # Check for suspicious ports
                    if port in [22, 3389, 5900]:  # SSH, RDP, VNC
                        threat_type = "Suspicious Port Connection"
                        description = f"Connection to suspicious port {port} from {ip}"
                        self.handle_threat(ip, threat_type, 2, description)
        except Exception as e:
            logger.error(f"Connection check error: {e}")
    
    def analyze_traffic_patterns(self):
        try:
            # Analyze traffic patterns for anomalies
            for ip, traffic in self.traffic_data.items():
                # Check for port scanning behavior
                if ip in self.connections and len(self.connections[ip]['ports']) > 5:
                    threat_type = "Possible Port Scanning"
                    description = f"IP {ip} connected to {len(self.connections[ip]['ports'])} different ports"
                    self.handle_threat(ip, threat_type, 2, description)
                
                # Check for data exfiltration
                total_sent = sum(t['bytes_sent'] for t in traffic.values())
                total_received = sum(t['bytes_received'] for t in traffic.values())
                
                if total_sent > 10 * 1024 * 1024:  # 10MB sent
                    threat_type = "Possible Data Exfiltration"
                    description = f"IP {ip} has sent {total_sent/1024/1024:.2f}MB of data"
                    self.handle_threat(ip, threat_type, 3, description)
        except Exception as e:
            logger.error(f"Traffic pattern analysis error: {e}")
    
    def check_external_threat_feeds(self):
        # In a real implementation, this would check external threat intelligence feeds
        pass
    
    # Telegram integration
    def send_telegram_alert(self, message):
        if not self.config['telegram']['token'] or not self.config['telegram']['chat_id']:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.config['telegram']['token']}/sendMessage"
            params = {
                'chat_id': self.config['telegram']['chat_id'],
                'text': message
            }
            
            response = requests.post(url, params=params)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Telegram alert error: {e}")
            return False
    
    def test_telegram_connection(self):
        if not self.config['telegram']['token'] or not self.config['telegram']['chat_id']:
            return False, "Telegram not configured"
            
        try:
            url = f"https://api.telegram.org/bot{self.config['telegram']['token']}/getMe"
            response = requests.get(url)
            
            if response.status_code == 200:
                return True, "Telegram connection successful"
            else:
                return False, f"Telegram API error: {response.text}"
        except Exception as e:
            return False, f"Telegram connection error: {e}"
    
    # GUI implementation
    def start_gui(self):
        self.root = tk.Tk()
        self.root.title("Accurate Cyber Defense Proxy Firewall")
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Apply theme
        self.apply_theme()
        
        # Create menu
        self.create_menu()
        
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook (tabs)
        self.tabs = ttk.Notebook(main_frame)
        self.tabs.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard tab
        dashboard_tab = ttk.Frame(self.tabs)
        self.tabs.add(dashboard_tab, text="Dashboard")
        
        # Create dashboard layout
        self.create_dashboard(dashboard_tab)
        
        # Logs tab
        logs_tab = ttk.Frame(self.tabs)
        self.tabs.add(logs_tab, text="Logs")
        
        # Create logs layout
        self.create_logs_tab(logs_tab)
        
        # Traffic tab
        traffic_tab = ttk.Frame(self.tabs)
        self.tabs.add(traffic_tab, text="Traffic")
        
        # Create traffic layout
        self.create_traffic_tab(traffic_tab)
        
        # Threats tab
        threats_tab = ttk.Frame(self.tabs)
        self.tabs.add(threats_tab, text="Threats")
        
        # Create threats layout
        self.create_threats_tab(threats_tab)
        
        # CLI tab
        cli_tab = ttk.Frame(self.tabs)
        self.tabs.add(cli_tab, text="CLI")
        
        # Create CLI layout
        self.create_cli_tab(cli_tab)
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Start GUI update thread
        threading.Thread(target=self.update_gui, daemon=True).start()
        
        # Start the main loop
        self.root.mainloop()
    
    def apply_theme(self):
        if self.config['ui']['theme'] == 'purple_black':
            self.root.configure(bg='#1a1a1a')
            
            style = ttk.Style()
            style.theme_use('clam')
            
            # Configure colors
            style.configure('.', background='#1a1a1a', foreground='#ffffff')
            style.configure('TNotebook', background='#1a1a1a', borderwidth=0)
            style.configure('TNotebook.Tab', background='#2a2a2a', foreground='#ffffff', padding=[10, 5])
            style.map('TNotebook.Tab', background=[('selected', '#4b0082')])
            style.configure('TFrame', background='#1a1a1a')
            style.configure('TLabel', background='#1a1a1a', foreground='#ffffff')
            style.configure('TButton', background='#4b0082', foreground='#ffffff', borderwidth=1)
            style.map('TButton', background=[('active', '#5a00a3')])
            style.configure('TEntry', fieldbackground='#2a2a2a', foreground='#ffffff')
            style.configure('TCombobox', fieldbackground='#2a2a2a', foreground='#ffffff')
            style.configure('TScrollbar', background='#2a2a2a')
            style.configure('Treeview', background='#2a2a2a', foreground='#ffffff', fieldbackground='#2a2a2a')
            style.configure('Treeview.Heading', background='#4b0082', foreground='#ffffff')
            style.map('Treeview', background=[('selected', '#4b0082')])
            style.configure('Vertical.TScrollbar', background='#2a2a2a')
            style.configure('Horizontal.TScrollbar', background='#2a2a2a')
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Start Proxy", command=self.start_proxy)
        tools_menu.add_command(label="Stop Proxy", command=self.stop_proxy)
        tools_menu.add_separator()
        tools_menu.add_command(label="Start Monitoring", command=self.start_monitoring)
        tools_menu.add_command(label="Stop Monitoring", command=self.stop_monitoring)
        tools_menu.add_separator()
        tools_menu.add_command(label="Block IP...", command=self.show_block_ip_dialog)
        tools_menu.add_command(label="Unblock IP...", command=self.show_unblock_ip_dialog)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Refresh", command=self.refresh_views)
        view_menu.add_separator()
        
        theme_menu = tk.Menu(view_menu, tearoff=0)
        theme_menu.add_radiobutton(label="Purple/Black", variable=tk.StringVar(value=self.config['ui']['theme']), 
                                 command=lambda: self.change_theme('purple_black'))
        theme_menu.add_radiobutton(label="System Default", variable=tk.StringVar(value=self.config['ui']['theme']), 
                                 command=lambda: self.change_theme('default'))
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Proxy Settings...", command=self.show_proxy_settings)
        settings_menu.add_command(label="Monitoring Settings...", command=self.show_monitoring_settings)
        settings_menu.add_command(label="Telegram Settings...", command=self.show_telegram_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard(self, parent):
        # Top frame for stats
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Stats widgets
        ttk.Label(stats_frame, text="Active Connections:", font=('Helvetica', 10, 'bold')).grid(row=0, column=0, sticky=tk.W)
        self.active_conn_label = ttk.Label(stats_frame, text="0")
        self.active_conn_label.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Blocked IPs:", font=('Helvetica', 10, 'bold')).grid(row=0, column=2, sticky=tk.W, padx=10)
        self.blocked_ips_label = ttk.Label(stats_frame, text="0")
        self.blocked_ips_label.grid(row=0, column=3, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Threats Detected:", font=('Helvetica', 10, 'bold')).grid(row=0, column=4, sticky=tk.W, padx=10)
        self.threats_label = ttk.Label(stats_frame, text="0")
        self.threats_label.grid(row=0, column=5, sticky=tk.W)
        
        # Charts frame
        charts_frame = ttk.Frame(parent)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Traffic chart
        traffic_chart_frame = ttk.Frame(charts_frame)
        traffic_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        ttk.Label(traffic_chart_frame, text="Traffic Distribution", font=('Helvetica', 10, 'bold')).pack()
        
        self.traffic_fig, self.traffic_ax = plt.subplots(figsize=(5, 4), dpi=100)
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, master=traffic_chart_frame)
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Threat chart
        threat_chart_frame = ttk.Frame(charts_frame)
        threat_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        ttk.Label(threat_chart_frame, text="Threat Distribution", font=('Helvetica', 10, 'bold')).pack()
        
        self.threat_fig, self.threat_ax = plt.subplots(figsize=(5, 4), dpi=100)
        self.threat_canvas = FigureCanvasTkAgg(self.threat_fig, master=threat_chart_frame)
        self.threat_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Update charts
        self.update_charts()
    
    def create_logs_tab(self, parent):
        # Log text widget with scrollbar
        log_frame = ttk.Frame(parent)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(
            log_frame,
            wrap=tk.WORD,
            yscrollcommand=scrollbar.set,
            bg='#2a2a2a',
            fg='#ffffff',
            insertbackground='white'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=self.log_text.yview)
        
        # Configure tags for different log levels
        self.log_text.tag_config('INFO', foreground='white')
        self.log_text.tag_config('WARNING', foreground='yellow')
        self.log_text.tag_config('ERROR', foreground='red')
        self.log_text.tag_config('CRITICAL', foreground='red', underline=1)
        
        # Add existing logs
        self.load_logs()
    
    def create_traffic_tab(self, parent):
        # Traffic treeview with scrollbars
        traffic_frame = ttk.Frame(parent)
        traffic_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for traffic data
        columns = ('ip', 'timestamp', 'protocol', 'bytes_sent', 'bytes_received', 'domain', 'url')
        self.traffic_tree = ttk.Treeview(
            traffic_frame,
            columns=columns,
            show='headings',
            selectmode='browse'
        )
        
        # Define headings
        self.traffic_tree.heading('ip', text='IP Address')
        self.traffic_tree.heading('timestamp', text='Timestamp')
        self.traffic_tree.heading('protocol', text='Protocol')
        self.traffic_tree.heading('bytes_sent', text='Sent (bytes)')
        self.traffic_tree.heading('bytes_received', text='Received (bytes)')
        self.traffic_tree.heading('domain', text='Domain')
        self.traffic_tree.heading('url', text='URL')
        
        # Set column widths
        self.traffic_tree.column('ip', width=120)
        self.traffic_tree.column('timestamp', width=150)
        self.traffic_tree.column('protocol', width=80)
        self.traffic_tree.column('bytes_sent', width=100)
        self.traffic_tree.column('bytes_received', width=100)
        self.traffic_tree.column('domain', width=150)
        self.traffic_tree.column('url', width=200)
        
        # Add scrollbars
        yscroll = ttk.Scrollbar(traffic_frame, orient=tk.VERTICAL, command=self.traffic_tree.yview)
        xscroll = ttk.Scrollbar(traffic_frame, orient=tk.HORIZONTAL, command=self.traffic_tree.xview)
        self.traffic_tree.configure(yscroll=yscroll.set, xscroll=xscroll.set)
        
        # Grid layout
        self.traffic_tree.grid(row=0, column=0, sticky=tk.NSEW)
        yscroll.grid(row=0, column=1, sticky=tk.NS)
        xscroll.grid(row=1, column=0, sticky=tk.EW)
        
        traffic_frame.grid_rowconfigure(0, weight=1)
        traffic_frame.grid_columnconfigure(0, weight=1)
        
        # Load traffic data
        self.load_traffic_data()
    
    def create_threats_tab(self, parent):
        # Threats treeview with scrollbars
        threats_frame = ttk.Frame(parent)
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for threat data
        columns = ('ip', 'timestamp', 'type', 'severity', 'description', 'action')
        self.threats_tree = ttk.Treeview(
            threats_frame,
            columns=columns,
            show='headings',
            selectmode='browse'
        )
        
        # Define headings
        self.threats_tree.heading('ip', text='IP Address')
        self.threats_tree.heading('timestamp', text='Timestamp')
        self.threats_tree.heading('type', text='Threat Type')
        self.threats_tree.heading('severity', text='Severity')
        self.threats_tree.heading('description', text='Description')
        self.threats_tree.heading('action', text='Action Taken')
        
        # Set column widths
        self.threats_tree.column('ip', width=120)
        self.threats_tree.column('timestamp', width=150)
        self.threats_tree.column('type', width=150)
        self.threats_tree.column('severity', width=80)
        self.threats_tree.column('description', width=250)
        self.threats_tree.column('action', width=150)
        
        # Add scrollbars
        yscroll = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        xscroll = ttk.Scrollbar(threats_frame, orient=tk.HORIZONTAL, command=self.threats_tree.xview)
        self.threats_tree.configure(yscroll=yscroll.set, xscroll=xscroll.set)
        
        # Grid layout
        self.threats_tree.grid(row=0, column=0, sticky=tk.NSEW)
        yscroll.grid(row=0, column=1, sticky=tk.NS)
        xscroll.grid(row=1, column=0, sticky=tk.EW)
        
        threats_frame.grid_rowconfigure(0, weight=1)
        threats_frame.grid_columnconfigure(0, weight=1)
        
        # Load threat data
        self.load_threat_data()
    
    def create_cli_tab(self, parent):
        # CLI interface
        cli_frame = ttk.Frame(parent)
        cli_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Command history/output
        output_frame = ttk.Frame(cli_frame)
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.cli_output = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            bg='#2a2a2a',
            fg='#ffffff',
            insertbackground='white'
        )
        self.cli_output.pack(fill=tk.BOTH, expand=True)
        self.cli_output.config(state=tk.DISABLED)
        
        # Command input
        input_frame = ttk.Frame(cli_frame)
        input_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT)
        
        self.command_entry = ttk.Entry(input_frame)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.command_entry.bind('<Return>', self.execute_command)
        self.command_entry.bind('<Up>', self.command_history_up)
        self.command_entry.bind('<Down>', self.command_history_down)
        
        # Add welcome message
        self.cli_print("CyberShield Proxy Firewall CLI\nType 'help' for available commands\n")
    
    def cli_print(self, text):
        self.cli_output.config(state=tk.NORMAL)
        self.cli_output.insert(tk.END, text + "\n")
        self.cli_output.config(state=tk.DISABLED)
        self.cli_output.see(tk.END)
    
    def execute_command(self, event=None):
        command = self.command_entry.get().strip()
        self.command_entry.delete(0, tk.END)
        
        if not command:
            return
            
        # Add to history
        self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        # Display command
        self.cli_print(f"> {command}")
        
        # Process command
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == 'help':
                self.show_cli_help()
            elif cmd == 'ping':
                self.cli_ping(args)
            elif cmd == 'status':
                self.cli_status()
            elif cmd == 'start' and len(args) >= 2 and args[0].lower() == 'monitoring':
                ip = args[1]
                self.config['monitoring']['active_ips'].append(ip)
                self.save_config()
                self.cli_print(f"Started monitoring IP: {ip}")
            elif cmd == 'stop':
                self.cli_stop()
            elif cmd == 'config' and len(args) >= 3 and args[0].lower() == 'telegram':
                if args[1].lower() == 'token':
                    self.config['telegram']['token'] = args[2]
                    self.save_config()
                    self.cli_print("Telegram token configured")
                elif args[1].lower() == 'chat_id':
                    self.config['telegram']['chat_id'] = args[2]
                    self.save_config()
                    self.cli_print("Telegram chat ID configured")
            elif cmd == 'view':
                self.cli_view(args)
            elif cmd == 'traceroute':
                self.cli_traceroute(args)
            elif cmd == 'clear':
                self.cli_output.config(state=tk.NORMAL)
                self.cli_output.delete(1.0, tk.END)
                self.cli_output.config(state=tk.DISABLED)
            elif cmd == 'test' and len(args) >= 2 and args[0].lower() == 'telegram':
                success, message = self.test_telegram_connection()
                self.cli_print(f"Telegram test: {message}")
            elif cmd == 'export' and len(args) >= 2 and args[0].lower() == 'to' and args[1].lower() == 'telegram':
                self.export_to_telegram()
            else:
                self.cli_print(f"Unknown command: {cmd}. Type 'help' for available commands.")
        except Exception as e:
            self.cli_print(f"Error executing command: {e}")
    
    def command_history_up(self, event):
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
    
    def command_history_down(self, event):
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        elif self.command_history and self.history_index == len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
    
    def show_cli_help(self):
        help_text = """
Available commands:
  help                           - Show this help message
  ping <ip>                      - Ping an IP address
  status                         - Show proxy and monitoring status
  start monitoring <ip>          - Start monitoring a specific IP
  stop                           - Stop monitoring
  config telegram token <token>  - Configure Telegram bot token
  config telegram chat_id <id>   - Configure Telegram chat ID
  view [traffic|threats]         - View traffic or threats data
  traceroute <ip>                - Perform traceroute to IP
  clear                          - Clear CLI output
  test telegram connection       - Test Telegram connection
  export to telegram             - Export data to Telegram
"""
        self.cli_print(help_text)
    
    def cli_ping(self, args):
        if not args:
            self.cli_print("Usage: ping <ip>")
            return
            
        ip = args[0]
        try:
            response_time = ping3.ping(ip)
            if response_time is not None:
                self.cli_print(f"Ping to {ip}: {response_time:.2f} ms")
            else:
                self.cli_print(f"Ping to {ip} failed")
        except Exception as e:
            self.cli_print(f"Ping error: {e}")
    
    def cli_status(self):
        proxy_status = "running" if self.running else "stopped"
        monitoring_status = "active" if self.monitoring_thread and self.monitoring_thread.is_alive() else "inactive"
        blocked_ips = len(self.config['monitoring']['blocked_ips'])
        active_monitoring = len(self.config['monitoring']['active_ips'])
        
        status_text = f"""
Proxy Status: {proxy_status}
Monitoring Status: {monitoring_status}
Blocked IPs: {blocked_ips}
Active Monitoring: {active_monitoring}
"""
        self.cli_print(status_text)
    
    def cli_stop(self):
        self.stop_monitoring()
        self.cli_print("Monitoring stopped")
    
    def cli_view(self, args):
        if not args:
            self.cli_print("Usage: view [traffic|threats]")
            return
            
        view_type = args[0].lower()
        if view_type == 'traffic':
            # Show traffic summary
            total_traffic = sum(
                sum(t['bytes_sent'] + t['bytes_received'] for t in ip_data.values())
                for ip_data in self.traffic_data.values()
            )
            self.cli_print(f"Total traffic: {total_traffic} bytes")
        elif view_type == 'threats':
            # Show threats summary
            total_threats = sum(len(threats) for threats in self.threat_data.values())
            self.cli_print(f"Total threats detected: {total_threats}")
        else:
            self.cli_print(f"Unknown view type: {view_type}")
    
    def cli_traceroute(self, args):
        if not args:
            self.cli_print("Usage: traceroute <ip>")
            return
            
        ip = args[0]
        try:
            if platform.system() == "Windows":
                command = ["tracert", "-d", ip]
            else:
                command = ["traceroute", ip]
                
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.cli_print(output.strip())
            
            return_code = process.poll()
            if return_code != 0:
                error = process.stderr.read()
                self.cli_print(f"Traceroute error: {error}")
        except Exception as e:
            self.cli_print(f"Traceroute error: {e}")
    
    def export_to_telegram(self):
        if not self.config['telegram']['enabled']:
            self.cli_print("Telegram integration is not enabled")
            return
            
        # Create summary message
        total_traffic = sum(
            sum(t['bytes_sent'] + t['bytes_received'] for t in ip_data.values())
            for ip_data in self.traffic_data.values()
        )
        total_threats = sum(len(threats) for threats in self.threat_data.values())
        
        message = f"""
🚀 CyberShield Data Export 🚀

📊 Traffic Summary:
- Total bytes: {total_traffic}
- Unique IPs: {len(self.traffic_data)}

⚠️ Threat Summary:
- Total threats: {total_threats}
- Blocked IPs: {len(self.config['monitoring']['blocked_ips'])}
"""
        success = self.send_telegram_alert(message)
        if success:
            self.cli_print("Data exported to Telegram successfully")
        else:
            self.cli_print("Failed to export data to Telegram")
    
    # Data loading for GUI
    def load_logs(self):
        try:
            with open(LOG_FILE, 'r') as f:
                logs = f.readlines()
                for log in logs[-1000:]:  # Load last 1000 lines
                    self.add_log_to_gui(log.strip())
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
    
    def add_log_to_gui(self, log):
        if not self.log_text:
            return
            
        # Parse log level
        log_level = 'INFO'
        if 'WARNING' in log:
            log_level = 'WARNING'
        elif 'ERROR' in log:
            log_level = 'ERROR'
        elif 'CRITICAL' in log:
            log_level = 'CRITICAL'
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log + "\n", log_level)
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
    
    def load_traffic_data(self):
        if not self.traffic_tree:
            return
            
        # Clear existing data
        for item in self.traffic_tree.get_children():
            self.traffic_tree.delete(item)
        
        # Load from database
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                SELECT ip, timestamp, protocol, bytes_sent, bytes_received, domain, url 
                FROM traffic_data 
                ORDER BY timestamp DESC
                LIMIT 1000
            ''')
            
            for row in cursor.fetchall():
                self.traffic_tree.insert('', tk.END, values=row)
        except Exception as e:
            logger.error(f"Error loading traffic data: {e}")
    
    def load_threat_data(self):
        if not self.threats_tree:
            return
            
        # Clear existing data
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        # Load from database
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                SELECT ip, timestamp, threat_type, severity, description, action_taken 
                FROM threat_data 
                ORDER BY timestamp DESC
                LIMIT 1000
            ''')
            
            for row in cursor.fetchall():
                self.threats_tree.insert('', tk.END, values=row)
        except Exception as e:
            logger.error(f"Error loading threat data: {e}")
    
    def update_charts(self):
        # Update traffic chart
        protocols = {'HTTP': 0, 'HTTPS': 0, 'DNS': 0}
        for ip_data in self.traffic_data.values():
            for traffic in ip_data.values():
                protocols[traffic['protocol']] += traffic['bytes_sent'] + traffic['bytes_received']
        
        self.traffic_ax.clear()
        if sum(protocols.values()) > 0:
            self.traffic_ax.pie(
                protocols.values(),
                labels=protocols.keys(),
                autopct='%1.1f%%',
                colors=['#4b0082', '#800080', '#9370db']
            )
            self.traffic_ax.set_title('Traffic Distribution by Protocol')
        else:
            self.traffic_ax.text(0.5, 0.5, 'No traffic data', ha='center', va='center')
        self.traffic_canvas.draw()
        
        # Update threat chart
        threat_types = {}
        for ip_threats in self.threat_data.values():
            for threat in ip_threats:
                threat_type = threat['type']
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        self.threat_ax.clear()
        if threat_types:
            self.threat_ax.bar(
                threat_types.keys(),
                threat_types.values(),
                color=['#ff0000', '#ff4500', '#ff8c00']
            )
            self.threat_ax.set_title('Threat Distribution by Type')
            self.threat_ax.tick_params(axis='x', rotation=45)
        else:
            self.threat_ax.text(0.5, 0.5, 'No threat data', ha='center', va='center')
        self.threat_canvas.draw()
        
        # Update stats
        self.active_conn_label.config(text=str(len(self.connections)))
        self.blocked_ips_label.config(text=str(len(self.config['monitoring']['blocked_ips'])))
        self.threats_label.config(text=str(sum(len(t) for t in self.threat_data.values())))
    
    # GUI update thread
    def update_gui(self):
        while True:
            try:
                item = self.gui_update_queue.get_nowait()
                if item[0] == 'traffic':
                    self.load_traffic_data()
                    self.update_charts()
                elif item[0] == 'threat':
                    self.load_threat_data()
                    self.update_charts()
                elif item[0] == 'log':
                    self.add_log_to_gui(item[1])
            except queue.Empty:
                pass
                
            self.root.update()
            time.sleep(0.1)
    
    # Dialog windows
    def show_block_ip_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Block IP Address")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Reason:").grid(row=1, column=0, padx=5, pady=5)
        reason_entry = ttk.Entry(dialog)
        reason_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Duration (minutes):").grid(row=2, column=0, padx=5, pady=5)
        duration_entry = ttk.Entry(dialog)
        duration_entry.insert(0, "60")
        duration_entry.grid(row=2, column=1, padx=5, pady=5)
        
        def block_ip():
            ip = ip_entry.get().strip()
            reason = reason_entry.get().strip()
            duration = duration_entry.get().strip()
            
            try:
                duration = int(duration)
                if duration <= 0:
                    raise ValueError
                
                # Validate IP
                ipaddress.ip_address(ip)
                
                self.block_ip(ip, reason, duration)
                messagebox.showinfo("Success", f"IP {ip} blocked for {duration} minutes")
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid duration or IP address")
        
        ttk.Button(dialog, text="Block", command=block_ip).grid(row=3, column=0, columnspan=2, pady=5)
    
    def show_unblock_ip_dialog(self):
        if not self.config['monitoring']['blocked_ips']:
            messagebox.showinfo("Info", "No IPs are currently blocked")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("Unblock IP Address")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Select IP to unblock:").pack(padx=5, pady=5)
        
        ip_listbox = tk.Listbox(dialog)
        for ip in self.config['monitoring']['blocked_ips']:
            ip_listbox.insert(tk.END, ip)
        ip_listbox.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        def unblock_ip():
            selection = ip_listbox.curselection()
            if not selection:
                messagebox.showerror("Error", "Please select an IP to unblock")
                return
                
            ip = ip_listbox.get(selection[0])
            self.unblock_ip(ip)
            messagebox.showinfo("Success", f"IP {ip} unblocked")
            dialog.destroy()
        
        ttk.Button(dialog, text="Unblock", command=unblock_ip).pack(pady=5)
    
    def show_proxy_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Proxy Settings")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="HTTP Port:").grid(row=0, column=0, padx=5, pady=5)
        http_port_entry = ttk.Entry(dialog)
        http_port_entry.insert(0, str(self.config['proxy']['http_port']))
        http_port_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="HTTPS Port:").grid(row=1, column=0, padx=5, pady=5)
        https_port_entry = ttk.Entry(dialog)
        https_port_entry.insert(0, str(self.config['proxy']['https_port']))
        https_port_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="DNS Port:").grid(row=2, column=0, padx=5, pady=5)
        dns_port_entry = ttk.Entry(dialog)
        dns_port_entry.insert(0, str(self.config['proxy']['dns_port']))
        dns_port_entry.grid(row=2, column=1, padx=5, pady=5)
        
        proxy_enabled = tk.BooleanVar(value=self.config['proxy']['enabled'])
        ttk.Checkbutton(dialog, text="Enable Proxy", variable=proxy_enabled).grid(row=3, column=0, columnspan=2, pady=5)
        
        def save_settings():
            try:
                self.config['proxy']['http_port'] = int(http_port_entry.get())
                self.config['proxy']['https_port'] = int(https_port_entry.get())
                self.config['proxy']['dns_port'] = int(dns_port_entry.get())
                self.config['proxy']['enabled'] = proxy_enabled.get()
                self.save_config()
                
                messagebox.showinfo("Success", "Proxy settings saved. Restart proxy for changes to take effect.")
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Ports must be valid numbers")
        
        ttk.Button(dialog, text="Save", command=save_settings).grid(row=4, column=0, columnspan=2, pady=5)
    
    def show_monitoring_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Monitoring Settings")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Alert Threshold (requests/min):").grid(row=0, column=0, padx=5, pady=5)
        threshold_entry = ttk.Entry(dialog)
        threshold_entry.insert(0, str(self.config['monitoring']['alert_threshold']))
        threshold_entry.grid(row=0, column=1, padx=5, pady=5)
        
        def save_settings():
            try:
                self.config['monitoring']['alert_threshold'] = int(threshold_entry.get())
                self.save_config()
                messagebox.showinfo("Success", "Monitoring settings saved")
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Threshold must be a valid number")
        
        ttk.Button(dialog, text="Save", command=save_settings).grid(row=1, column=0, columnspan=2, pady=5)
    
    def show_telegram_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Telegram Settings")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Bot Token:").grid(row=0, column=0, padx=5, pady=5)
        token_entry = ttk.Entry(dialog)
        token_entry.insert(0, self.config['telegram']['token'])
        token_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Chat ID:").grid(row=1, column=0, padx=5, pady=5)
        chat_id_entry = ttk.Entry(dialog)
        chat_id_entry.insert(0, self.config['telegram']['chat_id'])
        chat_id_entry.grid(row=1, column=1, padx=5, pady=5)
        
        telegram_enabled = tk.BooleanVar(value=self.config['telegram']['enabled'])
        ttk.Checkbutton(dialog, text="Enable Telegram Alerts", variable=telegram_enabled).grid(row=2, column=0, columnspan=2, pady=5)
        
        def test_connection():
            token = token_entry.get().strip()
            chat_id = chat_id_entry.get().strip()
            
            if not token or not chat_id:
                messagebox.showerror("Error", "Token and Chat ID are required")
                return
                
            # Temporarily set config for test
            original_token = self.config['telegram']['token']
            original_chat_id = self.config['telegram']['chat_id']
            self.config['telegram']['token'] = token
            self.config['telegram']['chat_id'] = chat_id
            
            success, msg = self.test_telegram_connection()
            messagebox.showinfo("Test Result", msg)
            
            # Restore original config
            self.config['telegram']['token'] = original_token
            self.config['telegram']['chat_id'] = original_chat_id
        
        def save_settings():
            self.config['telegram']['token'] = token_entry.get().strip()
            self.config['telegram']['chat_id'] = chat_id_entry.get().strip()
            self.config['telegram']['enabled'] = telegram_enabled.get()
            self.save_config()
            
            messagebox.showinfo("Success", "Telegram settings saved")
            dialog.destroy()
        
        ttk.Button(dialog, text="Test Connection", command=test_connection).grid(row=3, column=0, pady=5)
        ttk.Button(dialog, text="Save", command=save_settings).grid(row=3, column=1, pady=5)
    
    def show_about(self):
        about_text = """
Accurate Cyber Defense Proxy Firewall

Version: 88.0
Author: Ian Carter Kulani
E-mail:iancarterkulani@gmail.com
phone:+265988061969
Description: A comprehensive proxy firewall tool for monitoring and protecting your network.

Features:
- HTTP/HTTPS/DNS proxy
- IP-based traffic monitoring
- Threat detection and alerting
- Telegram integration
- Graphical and command line interfaces
"""
        messagebox.showinfo("About AcurateCyberDefenseProxyFireWall", about_text)
    
    def show_documentation(self):
        doc_text = """
Accurate Cyber Defense Proxy Firewall Documentation

1. Dashboard:
- Displays overview of traffic, threats, and system status
- Shows charts for traffic distribution and threat types

2. Logs:
- View system logs with different severity levels
- Auto-updates as new logs are generated

3. Traffic:
- Detailed view of all captured traffic
- Filterable by IP, protocol, time, etc.

4. Threats:
- View all detected threats
- See actions taken for each threat

5. CLI:
- Command line interface for quick operations
- Type 'help' for available commands

Commands:
- ping <ip>: Ping an IP address
- status: Show system status
- start monitoring <ip>: Start monitoring an IP
- config telegram token/chat_id: Configure Telegram
- view traffic/threats: View data
- traceroute <ip>: Perform traceroute
- test telegram connection: Test Telegram
- export to telegram: Export data to Telegram
"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Documentation")
        dialog.transient(self.root)
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, width=80, height=30)
        text.insert(tk.INSERT, doc_text)
        text.config(state=tk.DISABLED)
        text.pack(padx=10, pady=10)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
    
    # Utility methods
    def change_theme(self, theme):
        self.config['ui']['theme'] = theme
        self.save_config()
        self.apply_theme()
    
    def refresh_views(self):
        self.load_traffic_data()
        self.load_threat_data()
        self.update_charts()
        self.load_logs()
    
    def export_data(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write traffic data
                writer.writerow(["Traffic Data"])
                writer.writerow(["IP", "Timestamp", "Protocol", "Bytes Sent", "Bytes Received", "Domain", "URL"])
                
                cursor = self.db_conn.cursor()
                cursor.execute('SELECT * FROM traffic_data ORDER BY timestamp DESC')
                for row in cursor.fetchall():
                    writer.writerow(row[1:])  # Skip ID column
                
                # Write threat data
                writer.writerow([])
                writer.writerow(["Threat Data"])
                writer.writerow(["IP", "Timestamp", "Threat Type", "Severity", "Description", "Action Taken"])
                
                cursor.execute('SELECT * FROM threat_data ORDER BY timestamp DESC')
                for row in cursor.fetchall():
                    writer.writerow(row[1:])  # Skip ID column
                
                messagebox.showinfo("Success", f"Data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {e}")
    
    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to quit Proxy Firewall"):
            self.stop_proxy()
            self.stop_monitoring()
            self.db_conn.close()
            self.root.destroy()

# Main entry point
if __name__ == "__main__":
    firewall = AccurateCyberDefenseProxyFirewall()