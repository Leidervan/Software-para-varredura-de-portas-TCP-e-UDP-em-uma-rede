"""
Port Scanner Avançado - Varredura de portas TCP e UDP
Autor: Enhanced Version
Descrição: Ferramenta avançada para varredura de portas com interface moderna
Requisitos: Python 3.x, tkinter, threading
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from typing import List, Dict, Tuple
import time
from datetime import datetime
import queue
import os
import sys

# Portas comuns e seus serviços
COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
    119: 'NNTP', 123: 'NTP', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    161: 'SNMP', 194: 'IRC', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 515: 'LPD', 587: 'SMTP', 631: 'IPP', 636: 'LDAPS',
    873: 'Rsync', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN',
    1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS', 2082: 'cPanel',
    2083: 'cPanel SSL', 2086: 'WHM', 2087: 'WHM SSL', 3306: 'MySQL',
    3389: 'RDP', 3690: 'SVN', 4333: 'mSQL', 4444: 'Metasploit', 5000: 'UPnP',
    5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis',
    6666: 'IRC', 6667: 'IRC', 7000: 'Cassandra', 8000: 'HTTP-Alt',
    8008: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8081: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt', 9000: 'SonarQube', 9090: 'Prometheus', 9200: 'Elasticsearch',
    10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB', 28017: 'MongoDB Web',
    50000: 'SAP'
}

class PortScanner:
    """Classe principal para varredura de portas"""
    
    def __init__(self):
        self.stop_scan = False
        self.scan_queue = queue.Queue()
        self.results = {}
        self.lock = threading.Lock()
        
    def get_service_name(self, port: int) -> str:
        """Retorna o nome do serviço associado à porta"""
        return COMMON_PORTS.get(port, 'Unknown')
    
    def scan_tcp(self, ip: str, port: int, timeout: float = 1.0) -> Tuple[str, str]:
        """Varredura TCP com detecção de banner"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            
            if result == 0:
                # Tenta capturar o banner
                banner = ""
                try:
                    s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner_data = s.recv(1024)
                    if banner_data:
                        banner = banner_data.decode('utf-8', errors='ignore').strip()[:50]
                except:
                    pass
                s.close()
                return 'open', banner
            else:
                s.close()
                return 'closed', ''
        except socket.timeout:
            return 'filtered', ''
        except Exception as e:
            return 'error', str(e)
    
    def scan_udp(self, ip: str, port: int, timeout: float = 1.0) -> Tuple[str, str]:
        """Varredura UDP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            
            # Envia pacote vazio
            s.sendto(b'', (ip, port))
            
            try:
                data, _ = s.recvfrom(1024)
                s.close()
                return 'open', ''
            except socket.timeout:
                s.close()
                return 'open|filtered', ''
        except Exception as e:
            return 'error', str(e)
    
    def scan_port_worker(self, ip: str, proto: str, timeout: float, 
                        progress_callback=None, result_callback=None):
        """Worker thread para varredura de portas"""
        while not self.stop_scan:
            try:
                port = self.scan_queue.get(timeout=0.1)
            except queue.Empty:
                break
            
            if proto == 'tcp':
                status, banner = self.scan_tcp(ip, port, timeout)
            else:
                status, banner = self.scan_udp(ip, port, timeout)
            
            service = self.get_service_name(port)
            
            with self.lock:
                self.results[port] = {
                    'status': status,
                    'service': service,
                    'banner': banner
                }
            
            if result_callback:
                result_callback(port, status, service, banner)
            
            if progress_callback:
                progress_callback()
            
            self.scan_queue.task_done()
    
    def scan_ports(self, ip: str, ports: List[int], proto: str = 'tcp', 
                  timeout: float = 1.0, threads: int = 50,
                  progress_callback=None, result_callback=None):
        """Varredura multi-thread de portas"""
        self.stop_scan = False
        self.results = {}
        
        # Adiciona portas à fila
        for port in ports:
            self.scan_queue.put(port)
        
        # Cria threads de varredura
        workers = []
        num_threads = min(threads, len(ports))
        
        for _ in range(num_threads):
            t = threading.Thread(
                target=self.scan_port_worker,
                args=(ip, proto, timeout, progress_callback, result_callback)
            )
            t.daemon = True
            t.start()
            workers.append(t)
        
        # Aguarda conclusão
        for t in workers:
            t.join()
        
        return self.results
    
    def stop(self):
        """Para a varredura"""
        self.stop_scan = True

class ModernPortScannerGUI:
    """Interface gráfica moderna para o Port Scanner"""
    
    def __init__(self):
        self.scanner = PortScanner()
        self.scan_thread = None
        self.total_ports = 0
        self.scanned_ports = 0
        
        self.setup_gui()
        self.setup_styles()
        
    def setup_gui(self):
        """Configura a interface principal"""
        self.root = tk.Tk()
        self.root.title("🔍 Advanced Port Scanner Pro")
        self.root.geometry("900x700")
        
        # Configurar ícone se possível
        try:
            self.root.iconbitmap(default='icon.ico')
        except:
            pass
        
        # Frame principal com gradiente simulado
        self.main_frame = tk.Frame(self.root, bg='#1e1e2e')
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self.create_header()
        
        # Área de entrada
        self.create_input_area()
        
        # Área de controles
        self.create_control_area()
        
        # Área de progresso
        self.create_progress_area()
        
        # Área de resultados
        self.create_results_area()
        
        # Status bar
        self.create_status_bar()
        
    def setup_styles(self):
        """Configura estilos personalizados"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Cores do tema escuro
        bg_color = '#1e1e2e'
        fg_color = '#cdd6f4'
        accent_color = '#89b4fa'
        button_color = '#313244'
        hover_color = '#45475a'
        
        # Frame
        style.configure('Dark.TFrame', background=bg_color)
        
        # Labels
        style.configure('Header.TLabel', background=bg_color, foreground=accent_color,
                       font=('Segoe UI', 24, 'bold'))
        style.configure('Dark.TLabel', background=bg_color, foreground=fg_color,
                       font=('Segoe UI', 10))
        
        # Entry
        style.configure('Dark.TEntry', fieldbackground=button_color, foreground=fg_color,
                       insertcolor=fg_color, font=('Segoe UI', 10))
        
        # Combobox
        style.configure('Dark.TCombobox', fieldbackground=button_color, foreground=fg_color,
                       background=button_color, font=('Segoe UI', 10))
        style.map('Dark.TCombobox', fieldbackground=[('readonly', button_color)])
        
        # Buttons
        style.configure('Accent.TButton', background=accent_color, foreground=bg_color,
                       font=('Segoe UI', 11, 'bold'), borderwidth=0, relief='flat')
        style.map('Accent.TButton', background=[('active', hover_color)])
        
        style.configure('Danger.TButton', background='#f38ba8', foreground=bg_color,
                       font=('Segoe UI', 11, 'bold'), borderwidth=0, relief='flat')
        style.map('Danger.TButton', background=[('active', '#eba0ac')])
        
        # Progressbar
        style.configure('Dark.Horizontal.TProgressbar', background=accent_color,
                       troughcolor=button_color, borderwidth=0, lightcolor=accent_color,
                       darkcolor=accent_color)
        
        # Treeview
        style.configure('Dark.Treeview', background=button_color, foreground=fg_color,
                       fieldbackground=button_color, font=('Segoe UI', 10))
        style.configure('Dark.Treeview.Heading', background=bg_color, foreground=accent_color,
                       font=('Segoe UI', 10, 'bold'))
        style.map('Dark.Treeview', background=[('selected', hover_color)])
        
    def create_header(self):
        """Cria o cabeçalho da aplicação"""
        header_frame = tk.Frame(self.main_frame, bg='#1e1e2e', height=80)
        header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        # Título principal
        title = tk.Label(header_frame, text="🔍 Advanced Port Scanner Pro",
                        font=('Segoe UI', 26, 'bold'), bg='#1e1e2e', fg='#89b4fa')
        title.pack(side=tk.LEFT)
        
        # Informações
        info_frame = tk.Frame(header_frame, bg='#1e1e2e')
        info_frame.pack(side=tk.RIGHT)
        
        self.time_label = tk.Label(info_frame, text="", font=('Segoe UI', 10),
                                  bg='#1e1e2e', fg='#a6adc8')
        self.time_label.pack()
        
        self.update_time()
        
    def create_input_area(self):
        """Cria área de entrada de dados"""
        input_frame = ttk.Frame(self.main_frame, style='Dark.TFrame')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Grid de inputs
        grid_frame = ttk.Frame(input_frame, style='Dark.TFrame')
        grid_frame.pack(fill=tk.X)
        
        # IP Address
        ttk.Label(grid_frame, text="🖥️ Target IP:", style='Dark.TLabel').grid(
            row=0, column=0, sticky='w', padx=(0, 10), pady=5)
        self.ip_entry = ttk.Entry(grid_frame, style='Dark.TEntry', width=20)
        self.ip_entry.grid(row=0, column=1, sticky='ew', pady=5)
        self.ip_entry.insert(0, "127.0.0.1")
        
        # Ports
        ttk.Label(grid_frame, text="🔌 Ports:", style='Dark.TLabel').grid(
            row=0, column=2, sticky='w', padx=(20, 10), pady=5)
        self.ports_entry = ttk.Entry(grid_frame, style='Dark.TEntry', width=20)
        self.ports_entry.grid(row=0, column=3, sticky='ew', pady=5)
        self.ports_entry.insert(0, "1-1000")
        
        # Protocol
        ttk.Label(grid_frame, text="📡 Protocol:", style='Dark.TLabel').grid(
            row=1, column=0, sticky='w', padx=(0, 10), pady=5)
        self.proto_var = tk.StringVar(value='tcp')
        self.proto_combo = ttk.Combobox(grid_frame, textvariable=self.proto_var,
                                        values=['tcp', 'udp'], state='readonly',
                                        style='Dark.TCombobox', width=18)
        self.proto_combo.grid(row=1, column=1, sticky='ew', pady=5)
        
        # Timeout
        ttk.Label(grid_frame, text="⏱️ Timeout (s):", style='Dark.TLabel').grid(
            row=1, column=2, sticky='w', padx=(20, 10), pady=5)
        self.timeout_entry = ttk.Entry(grid_frame, style='Dark.TEntry', width=20)
        self.timeout_entry.grid(row=1, column=3, sticky='ew', pady=5)
        self.timeout_entry.insert(0, "1.0")
        
        # Threads
        ttk.Label(grid_frame, text="⚡ Threads:", style='Dark.TLabel').grid(
            row=2, column=0, sticky='w', padx=(0, 10), pady=5)
        self.threads_entry = ttk.Entry(grid_frame, style='Dark.TEntry', width=20)
        self.threads_entry.grid(row=2, column=1, sticky='ew', pady=5)
        self.threads_entry.insert(0, "50")
        
        # Quick scan presets
        ttk.Label(grid_frame, text="🎯 Quick Scan:", style='Dark.TLabel').grid(
            row=2, column=2, sticky='w', padx=(20, 10), pady=5)
        preset_frame = tk.Frame(grid_frame, bg='#1e1e2e')
        preset_frame.grid(row=2, column=3, sticky='ew', pady=5)
        
        tk.Button(preset_frame, text="Common", command=lambda: self.set_preset('common'),
                 bg='#313244', fg='#cdd6f4', font=('Segoe UI', 9), bd=0,
                 activebackground='#45475a').pack(side=tk.LEFT, padx=2)
        tk.Button(preset_frame, text="Web", command=lambda: self.set_preset('web'),
                 bg='#313244', fg='#cdd6f4', font=('Segoe UI', 9), bd=0,
                 activebackground='#45475a').pack(side=tk.LEFT, padx=2)
        tk.Button(preset_frame, text="Full", command=lambda: self.set_preset('full'),
                 bg='#313244', fg='#cdd6f4', font=('Segoe UI', 9), bd=0,
                 activebackground='#45475a').pack(side=tk.LEFT, padx=2)
        
        # Configure grid weights
        grid_frame.columnconfigure(1, weight=1)
        grid_frame.columnconfigure(3, weight=1)
        
    def create_control_area(self):
        """Cria área de botões de controle"""
        control_frame = ttk.Frame(self.main_frame, style='Dark.TFrame')
        control_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Botões principais
        button_frame = tk.Frame(control_frame, bg='#1e1e2e')
        button_frame.pack()
        
        self.scan_btn = ttk.Button(button_frame, text="🚀 Start Scan",
                                  command=self.start_scan, style='Accent.TButton',
                                  width=15)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="⏹️ Stop Scan",
                                   command=self.stop_scan, style='Danger.TButton',
                                   width=15, state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="🗑️ Clear Results",
                  command=self.clear_results, style='Accent.TButton',
                  width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="💾 Export Results",
                  command=self.export_results, style='Accent.TButton',
                  width=15).pack(side=tk.LEFT, padx=5)
        
    def create_progress_area(self):
        """Cria área de progresso"""
        progress_frame = ttk.Frame(self.main_frame, style='Dark.TFrame')
        progress_frame.pack(fill=tk.X, padx=20, pady=5)
        
        # Label de progresso
        self.progress_label = ttk.Label(progress_frame, text="Ready to scan",
                                       style='Dark.TLabel')
        self.progress_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # Barra de progresso
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate',
                                           style='Dark.Horizontal.TProgressbar')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Porcentagem
        self.percent_label = ttk.Label(progress_frame, text="0%", style='Dark.TLabel')
        self.percent_label.pack(side=tk.LEFT, padx=(10, 0))
        
    def create_results_area(self):
        """Cria área de resultados com Treeview"""
        results_frame = ttk.Frame(self.main_frame, style='Dark.TFrame')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Frame para o Treeview e scrollbar
        tree_frame = tk.Frame(results_frame, bg='#313244')
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(tree_frame)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        h_scroll = ttk.Scrollbar(tree_frame, orient='horizontal')
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Treeview
        columns = ('Port', 'Status', 'Service', 'Banner/Info')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                style='Dark.Treeview', yscrollcommand=v_scroll.set,
                                xscrollcommand=h_scroll.set)
        
        # Configurar colunas
        self.tree.heading('Port', text='Port')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Service', text='Service')
        self.tree.heading('Banner/Info', text='Banner/Info')
        
        self.tree.column('Port', width=80, anchor='center')
        self.tree.column('Status', width=100, anchor='center')
        self.tree.column('Service', width=150, anchor='w')
        self.tree.column('Banner/Info', width=400, anchor='w')
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        v_scroll.config(command=self.tree.yview)
        h_scroll.config(command=self.tree.xview)
        
        # Tags para cores diferentes
        self.tree.tag_configure('open', foreground='#a6e3a1')
        self.tree.tag_configure('closed', foreground='#f38ba8')
        self.tree.tag_configure('filtered', foreground='#f9e2af')
        
    def create_status_bar(self):
        """Cria barra de status"""
        status_frame = tk.Frame(self.main_frame, bg='#313244', height=30)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(status_frame, text="Ready", bg='#313244',
                                    fg='#a6adc8', font=('Segoe UI', 9))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.stats_label = tk.Label(status_frame, text="", bg='#313244',
                                   fg='#a6adc8', font=('Segoe UI', 9))
        self.stats_label.pack(side=tk.RIGHT, padx=10)
        
    def update_time(self):
        """Atualiza o relógio"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=now)
        self.root.after(1000, self.update_time)
        
    def set_preset(self, preset):
        """Define presets de varredura"""
        presets = {
            'common': '21-23,25,53,80,110,139,143,443,445,3306,3389,8080',
            'web': '80,443,8000,8008,8080,8443,8888',
            'full': '1-65535'
        }
        self.ports_entry.delete(0, tk.END)
        self.ports_entry.insert(0, presets.get(preset, '1-1000'))
        
    def parse_ports(self, ports_str):
        """Analisa string de portas"""
        ports = []
        parts = ports_str.split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                except:
                    continue
            else:
                try:
                    ports.append(int(part))
                except:
                    continue
        
        return sorted(set(ports))
    
    def start_scan(self):
        """Inicia a varredura"""
        # Validação de entrada
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter a valid IP address")
            return
        
        ports_str = self.ports_entry.get().strip()
        ports = self.parse_ports(ports_str)
        if not ports:
            messagebox.showerror("Error", "Please enter valid ports")
            return
        
        try:
            timeout = float(self.timeout_entry.get().strip())
            threads = int(self.threads_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid timeout or threads value")
            return
        
        # Limpar resultados anteriores
        self.clear_results()
        
        # Atualizar interface
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_label.config(text=f"Scanning {ip}...")
        
        # Configurar progresso
        self.total_ports = len(ports)
        self.scanned_ports = 0
        self.progress_bar['maximum'] = self.total_ports
        self.progress_bar['value'] = 0
        
        # Iniciar varredura em thread separada
        proto = self.proto_var.get()
        
        def scan_thread():
            start_time = time.time()
            
            self.scanner.scan_ports(
                ip, ports, proto, timeout, threads,
                progress_callback=self.update_progress,
                result_callback=self.add_result
            )
            
            elapsed = time.time() - start_time
            self.root.after(0, self.scan_complete, elapsed)
        
        self.scan_thread = threading.Thread(target=scan_thread)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def stop_scan(self):
        """Para a varredura"""
        self.scanner.stop()
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text="Scan stopped")
        
    def update_progress(self):
        """Atualiza o progresso da varredura"""
        self.scanned_ports += 1
        self.root.after(0, self._update_progress_ui)
        
    def _update_progress_ui(self):
        """Atualiza a UI do progresso"""
        self.progress_bar['value'] = self.scanned_ports
        percent = (self.scanned_ports / self.total_ports) * 100
        self.percent_label.config(text=f"{percent:.1f}%")
        self.progress_label.config(text=f"Scanned {self.scanned_ports}/{self.total_ports} ports")
        
    def add_result(self, port, status, service, banner):
        """Adiciona resultado ao Treeview"""
        self.root.after(0, self._add_result_ui, port, status, service, banner)
        
    def _add_result_ui(self, port, status, service, banner):
        """Adiciona resultado na UI"""
        if status == 'open':
            tag = 'open'
            self.tree.insert('', 0, values=(port, status.upper(), service, banner), tags=(tag,))
        elif status in ['filtered', 'open|filtered']:
            tag = 'filtered'
            self.tree.insert('', 'end', values=(port, status.upper(), service, banner), tags=(tag,))
        
        # Atualizar estatísticas
        self.update_stats()
        
    def update_stats(self):
        """Atualiza estatísticas"""
        open_ports = len([item for item in self.tree.get_children() 
                         if 'open' in self.tree.item(item)['tags']])
        filtered_ports = len([item for item in self.tree.get_children() 
                            if 'filtered' in self.tree.item(item)['tags']])
        
        self.stats_label.config(text=f"Open: {open_ports} | Filtered: {filtered_ports}")
        
    def scan_complete(self, elapsed_time):
        """Finaliza a varredura"""
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text=f"Scan completed in {elapsed_time:.2f} seconds")
        self.progress_label.config(text="Scan complete")
        
        # Mostrar resumo
        open_ports = len([item for item in self.tree.get_children() 
                         if 'open' in self.tree.item(item)['tags']])
        messagebox.showinfo("Scan Complete", 
                          f"Scan completed!\n\nTime: {elapsed_time:.2f}s\n"
                          f"Open ports found: {open_ports}")
        
    def clear_results(self):
        """Limpa os resultados"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress_bar['value'] = 0
        self.percent_label.config(text="0%")
        self.progress_label.config(text="Ready to scan")
        self.stats_label.config(text="")
        
    def export_results(self):
        """Exporta resultados para arquivo"""
        if not self.tree.get_children():
            messagebox.showwarning("Warning", "No results to export")
            return
        
        from tkinter import filedialog
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(f"Port Scanner Results\n")
                    f.write(f"Target: {self.ip_entry.get()}\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("-" * 80 + "\n\n")
                    
                    if filename.endswith('.csv'):
                        f.write("Port,Status,Service,Banner\n")
                        for item in self.tree.get_children():
                            values = self.tree.item(item)['values']
                            f.write(f"{values[0]},{values[1]},{values[2]},{values[3]}\n")
                    else:
                        f.write(f"{'Port':<10} {'Status':<15} {'Service':<20} {'Banner':<50}\n")
                        f.write("-" * 80 + "\n")
                        for item in self.tree.get_children():
                            values = self.tree.item(item)['values']
                            f.write(f"{values[0]:<10} {values[1]:<15} {values[2]:<20} {values[3]:<50}\n")
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")
    
    def run(self):
        """Inicia a aplicação"""
        self.root.mainloop()


class QuickScanDialog:
    """Diálogo para varredura rápida de portas comuns"""
    
    def __init__(self, parent, scanner_gui):
        self.scanner_gui = scanner_gui
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Quick Scan - Common Services")
        self.dialog.geometry("400x500")
        self.dialog.configure(bg='#1e1e2e')
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets()
        
    def create_widgets(self):
        """Cria widgets do diálogo"""
        # Título
        title = tk.Label(self.dialog, text="Select Services to Scan",
                        font=('Segoe UI', 14, 'bold'), bg='#1e1e2e', fg='#89b4fa')
        title.pack(pady=10)
        
        # Frame com scrollbar
        frame = tk.Frame(self.dialog, bg='#1e1e2e')
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Listbox com checkboxes
        self.listbox = tk.Listbox(frame, selectmode=tk.MULTIPLE,
                                 bg='#313244', fg='#cdd6f4',
                                 font=('Segoe UI', 10),
                                 yscrollcommand=scrollbar.set)
        self.listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.listbox.yview)
        
        # Adicionar serviços comuns
        services = [
            "FTP (20-21)", "SSH (22)", "Telnet (23)", "SMTP (25)",
            "DNS (53)", "HTTP (80)", "POP3 (110)", "IMAP (143)",
            "HTTPS (443)", "SMB (445)", "MySQL (3306)", "RDP (3389)",
            "PostgreSQL (5432)", "VNC (5900)", "HTTP-Proxy (8080)",
            "MongoDB (27017)", "Elasticsearch (9200)"
        ]
        
        for service in services:
            self.listbox.insert(tk.END, service)
        
        # Botões
        button_frame = tk.Frame(self.dialog, bg='#1e1e2e')
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Select All", command=self.select_all,
                 bg='#313244', fg='#cdd6f4', font=('Segoe UI', 10),
                 bd=0, padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Clear All", command=self.clear_all,
                 bg='#313244', fg='#cdd6f4', font=('Segoe UI', 10),
                 bd=0, padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Start Scan", command=self.start_scan,
                 bg='#89b4fa', fg='#1e1e2e', font=('Segoe UI', 10, 'bold'),
                 bd=0, padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Cancel", command=self.dialog.destroy,
                 bg='#f38ba8', fg='#1e1e2e', font=('Segoe UI', 10, 'bold'),
                 bd=0, padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
    def select_all(self):
        """Seleciona todos os serviços"""
        self.listbox.selection_set(0, tk.END)
        
    def clear_all(self):
        """Limpa todas as seleções"""
        self.listbox.selection_clear(0, tk.END)
        
    def start_scan(self):
        """Inicia varredura com portas selecionadas"""
        selected = self.listbox.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Please select at least one service")
            return
        
        # Extrair portas dos serviços selecionados
        ports = []
        for idx in selected:
            service = self.listbox.get(idx)
            # Extrair número da porta do texto
            port_str = service.split('(')[1].split(')')[0]
            if '-' in port_str:
                start, end = map(int, port_str.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(port_str))
        
        # Atualizar campo de portas
        self.scanner_gui.ports_entry.delete(0, tk.END)
        self.scanner_gui.ports_entry.insert(0, ','.join(map(str, sorted(set(ports)))))
        
        # Fechar diálogo e iniciar varredura
        self.dialog.destroy()
        self.scanner_gui.start_scan()


def main():
    """Função principal"""
    app = ModernPortScannerGUI()
    
    # Centralizar janela
    app.root.update_idletasks()
    width = app.root.winfo_width()
    height = app.root.winfo_height()
    x = (app.root.winfo_screenwidth() // 2) - (width // 2)
    y = (app.root.winfo_screenheight() // 2) - (height // 2)
    app.root.geometry(f'{width}x{height}+{x}+{y}')
    
    app.run()


if __name__ == "__main__":
    main()