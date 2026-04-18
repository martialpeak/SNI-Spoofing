import asyncio
import os
import socket
import struct
import sys
import threading
import json
import queue
import time
import ipaddress
import tkinter as tk
import customtkinter as ctk
from tkinter import ttk, messagebox

# تنظیم تایم‌اوت سراسری شبکه
socket.setdefaulttimeout(3.0)

# تنظیمات تم مدرن
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# =====================================================================
# دیتابیس استاتیک و امضاهای DNS
# =====================================================================
IP_DATABASE = {
    "☁️ Cloudflare": ["103.21.244.0/22", "104.16.0.0/13", "108.162.192.0/18", "172.64.0.0/13", "188.114.96.0/20"],
    "⚡ ArvanCloud": ["185.143.232.0/22", "94.182.160.0/19", "185.176.4.0/22"],
    "🚀 Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "📦 Amazon AWS": ["3.5.0.0/16", "52.95.0.0/16", "54.239.0.0/16"],
    "🔍 Google Cloud": ["34.0.0.0/8", "35.0.0.0/8"],
    "💧 DigitalOcean": ["104.131.0.0/16", "138.197.0.0/16", "162.243.0.0/16"],
    "🦅 Vultr": ["108.61.0.0/16", "149.28.0.0/16", "207.246.64.0/18"],
    "🇩🇪 Hetzner": ["116.202.0.0/15", "135.181.0.0/16", "159.69.0.0/16"]
}

DNS_SIGNATURES = {
    "amazonaws.com": "📦 Amazon AWS", "digitalocean.com": "💧 DigitalOcean", 
    "vultr.com": "🦅 Vultr", "hetzner.com": "🇩🇪 Hetzner", "linode.com": "🟢 Linode", 
    "googleusercontent.com": "🔍 Google Cloud", "arvancloud": "⚡ ArvanCloud", 
    "cloudflare.com": "☁️ Cloudflare", "fastly.net": "🚀 Fastly"
}

def detect_provider(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for provider, ranges in IP_DATABASE.items():
            for subnet in ranges:
                if ip_obj in ipaddress.ip_network(subnet): return provider
    except: pass

    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        hostname = hostname.lower()
        for sig, name in DNS_SIGNATURES.items():
            if sig in hostname: return f"{name} (DNS)"
        parts = hostname.split('.')
        short_host = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        return f"🌐 {short_host} (DNS)"
    except: return "❓ Unknown"

# =====================================================================
# توابع پایه، لاگ‌گیر و TCP Ping هوشمند
# =====================================================================
def get_exe_dir():
    if getattr(sys, 'frozen', False): return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

LOG_FILE_PATH = os.path.join(get_exe_dir(), "debug.log")

def write_to_log_file(msg):
    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
            f.flush()
    except: pass

def get_tcp_ping(ip, port=443, timeout=1.5):
    """استفاده از اتصال TCP به جای پینگ ویندوز برای دور زدن محدودیت‌های ICMP"""
    try:
        start_time = time.time()
        with socket.create_connection((ip, port), timeout=timeout):
            pass
        return int((time.time() - start_time) * 1000)
    except:
        return 999

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

# =====================================================================
# هسته پکت‌ها و جعل SNI
# =====================================================================
try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
except ImportError:
    pass 

class ClientHelloMaker:
    tls_ch_template_str = (
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc"
        "90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8"
        "c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00"
        "160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e31001600"
        "0000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205"
        "020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e06134"
        "73e2338770efdaa98693d217001500d50000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    _clean = tls_ch_template_str.replace('\n', '').replace(' ', '')
    if len(_clean) % 2 != 0: _clean += "0"
    tls_ch_template = bytes.fromhex(_clean)

    @classmethod
    def get_client_hello_with(cls, rnd, sess_id, target_sni, key_share):
        template_sni = b"mci.ir"
        s1, s2, s3 = cls.tls_ch_template[:11], b"\x20", cls.tls_ch_template[76:120]
        s4 = cls.tls_ch_template[127 + len(template_sni):262 + len(template_sni)]
        sn_ext = struct.pack("!H", len(target_sni) + 5) + struct.pack("!H", len(target_sni) + 3) + b"\x00" + struct.pack("!H", len(target_sni)) + target_sni
        pad_ext = struct.pack("!H", 219 - len(target_sni)) + (b"\x00" * (219 - len(target_sni)))
        return s1 + rnd + s2 + sess_id + s3 + sn_ext + s4 + key_share + b"\x00\x15" + pad_ext

# =====================================================================
# متغیرهای سراسری
# =====================================================================
log_queue = queue.Queue()
async_loop_running = False
fake_injective_connections = {}
active_divert_ips = set() # جلوگیری از تداخل درایور در ری‌استارت‌های متعدد

def gui_log(source, message, level="INFO"):
    icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️", "Scanner": "🔍", "DPI": "🛡️", "Relay": "⚡"}
    icon = icons.get(level if level in icons else source, "🔹")
    log_queue.put((time.strftime("%H:%M:%S"), level, source, f"{icon} {message}"))
    write_to_log_file(f"[{level}] {source}: {message}")

# =====================================================================
# رابط کاربری اصلی
# =====================================================================
class ModernProxyGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SNI Ultimate TCP-Scanner & Proxy v3.5 - ROCK SOLID")
        self.geometry("1250x750")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.server_socket = None

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.logo = ctk.CTkLabel(self.sidebar, text="🧠 AI PROXY CORE", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        self.btn_scan = ctk.CTkButton(self.sidebar, text="🔍 SMART BATCH TEST", fg_color="#3498db", hover_color="#2980b9", height=40, command=self.start_bulk_scan)
        self.btn_scan.grid(row=1, column=0, padx=20, pady=10)
        
        self.info_lbl = ctk.CTkLabel(self.sidebar, text=f"Local IP:\n{get_local_ip()}", font=ctk.CTkFont(size=14, weight="bold"), text_color="#2ecc71")
        self.info_lbl.grid(row=2, column=0, padx=20, pady=20)

        self.btn_toggle = ctk.CTkButton(self.sidebar, text="▶️ START PROXY", fg_color="#2ecc71", hover_color="#27ae60", height=55, font=ctk.CTkFont(size=14, weight="bold"), command=self.toggle_proxy)
        self.btn_toggle.grid(row=5, column=0, padx=20, pady=30, sticky="s")

        # Main Workspace
        self.main_work = ctk.CTkFrame(self, corner_radius=15, fg_color="#141414")
        self.main_work.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_work.grid_rowconfigure(1, weight=1)
        self.main_work.grid_columnconfigure(0, weight=1)

        # Scanner Table
        ctk.CTkLabel(self.main_work, text="📊 Dynamic TCP Infrastructure Analysis", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="#ecf0f1", fieldbackground="#1a1a1a", rowheight=35, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#2d3436", foreground="white", relief="flat", font=("Segoe UI", 10, "bold"))

        self.scan_tree = ttk.Treeview(self.main_work, columns=("sni", "ip", "provider", "ping", "status"), show='headings', height=8)
        self.scan_tree.heading("sni", text="DOMAIN (SNI)")
        self.scan_tree.heading("ip", text="RESOLVED IP")
        self.scan_tree.heading("provider", text="DETECTED INFRASTRUCTURE")
        self.scan_tree.heading("ping", text="TCP LATENCY")
        self.scan_tree.heading("status", text="QUALITY")
        self.scan_tree.column("sni", width=220)
        self.scan_tree.column("ip", width=140, anchor="center")
        self.scan_tree.column("provider", width=220, anchor="w") 
        self.scan_tree.column("ping", width=100, anchor="center")
        self.scan_tree.column("status", width=120, anchor="center")
        self.scan_tree.grid(row=1, column=0, padx=20, pady=5, sticky="nsew")
        self.scan_tree.bind("<<TreeviewSelect>>", self.on_item_select)

        # Logs Table
        ctk.CTkLabel(self.main_work, text="🛠️ Engine Logs", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=20, pady=(15, 5), sticky="w")
        self.log_tree = ttk.Treeview(self.main_work, columns=("T", "L", "S", "M"), show='headings', height=8)
        self.log_tree.heading("T", text="TIME")
        self.log_tree.heading("L", text="LVL")
        self.log_tree.heading("S", text="SRC")
        self.log_tree.heading("M", text="MESSAGE")
        self.log_tree.column("T", width=90, anchor="center")
        self.log_tree.column("L", width=80, anchor="center")
        self.log_tree.column("S", width=100, anchor="center")
        self.log_tree.column("M", width=550)
        self.log_tree.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="nsew")
        
        self.after(100, self.update_logs)

    def add_scan_result_safe(self, sni, ip, provider, ping_str, quality):
        try: self.scan_tree.insert("", tk.END, values=(sni, ip, provider, ping_str, quality))
        except Exception as e: gui_log("System", f"UI Table Error: {str(e)}", "ERROR")

    def start_bulk_scan(self):
        self.btn_scan.configure(state="disabled", text="Analyzing TCP...")
        for i in self.scan_tree.get_children(): self.scan_tree.delete(i)
        
        def run():
            path = os.path.join(get_exe_dir(), "sni_list.txt")
            if not os.path.exists(path):
                with open(path, "w") as f: f.write("auth.vercel.com\ndiscord.com\ncloudflare.com")
            
            with open(path, "r") as f: snis = [l.strip() for l in f if l.strip()]
            gui_log("Scanner", f"Starting TCP Deep Scan for {len(snis)} nodes...", "INFO")
            
            for sni in snis:
                try:
                    ip = socket.gethostbyname(sni)
                    provider = detect_provider(ip)
                    ping = get_tcp_ping(ip)  # استفاده از پینگ جدید و قدرتمند TCP
                    
                    quality = "🟢 EXCELLENT" if ping < 200 else "🟡 STABLE"
                    if ping > 400: quality = "🟠 SLOW"
                    if ping == 999: quality = "🔴 OFFLINE"
                    
                    ping_str = f"{ping}ms" if ping < 999 else "---"
                    self.after(0, self.add_scan_result_safe, sni, ip, provider, ping_str, quality)
                except Exception as e:
                    self.after(0, self.add_scan_result_safe, sni, "Unresolved", "Unknown", "---", "🚫 BLOCKED")
            
            gui_log("Scanner", "TCP Analysis Complete.", "SUCCESS")
            self.after(0, lambda: self.btn_scan.configure(state="normal", text="🔍 SMART BATCH TEST"))

        threading.Thread(target=run, daemon=True).start()

    def on_item_select(self, event):
        selected = self.scan_tree.selection()
        if not selected: return
        data = self.scan_tree.item(selected[0])['values']
        sni, ip, prov = data[0], data[1], data[2]
        
        if ip == "Unresolved": return
        
        conf_path = os.path.join(get_exe_dir(), 'config.json')
        try:
            with open(conf_path, 'r+') as f:
                config = json.load(f)
                config['FAKE_SNI'], config['CONNECT_IP'] = sni, ip
                f.seek(0); json.dump(config, f, indent=4); f.truncate()
            gui_log("Config", f"Activated: {sni} -> {ip}", "SUCCESS")
        except: gui_log("Config", "Failed to update config.json", "ERROR")

    def update_logs(self):
        while not log_queue.empty():
            t, l, s, m = log_queue.get()
            self.log_tree.insert("", 0, values=(t, l, s, m))
            self.log_tree.yview_moveto(1)
        self.after(100, self.update_logs)

    # =====================================================================
    # بخش حیاتی پروکسی
    # =====================================================================
    def toggle_proxy(self):
        global async_loop_running, active_divert_ips
        if not async_loop_running:
            try:
                conf_path = os.path.join(get_exe_dir(), 'config.json')
                with open(conf_path) as f: config = json.load(f)
                
                async_loop_running = True
                self.btn_toggle.configure(text="🛑 STOP ENGINE", fg_color="#e74c3c", hover_color="#c0392b")
                
                target_ip = config["CONNECT_IP"]
                local_ip = get_local_ip()
                gui_log("System", f"Starting Proxy on Port {config['LISTEN_PORT']}", "INFO")

                threading.Thread(target=lambda: asyncio.run(self.run_srv(config, local_ip)), daemon=True).start()
                
                # مدیریت هوشمند پردازش WinDivert
                if "FakeTcpInjector" in globals():
                    if target_ip not in active_divert_ips:
                        w_filter = f"tcp and ((ip.SrcAddr == {local_ip} and ip.DstAddr == {target_ip}) or (ip.SrcAddr == {target_ip} and ip.DstAddr == {local_ip}))"
                        threading.Thread(target=FakeTcpInjector(w_filter, fake_injective_connections).run, daemon=True).start()
                        active_divert_ips.add(target_ip)
                        gui_log("DPI", f"WinDivert Engine Activated for {target_ip}", "SUCCESS")
                else:
                    gui_log("DPI", "WinDivert Module Missing! Bypass may fail.", "WARNING")

                gui_log("System", f"Engine Engaged! Ready for traffic.", "SUCCESS")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start proxy: {str(e)}")
        else:
            async_loop_running = False
            if self.server_socket:
                try: self.server_socket.close()
                except: pass
            
            fake_injective_connections.clear()
            self.btn_toggle.configure(text="▶️ START PROXY", fg_color="#2ecc71", hover_color="#27ae60")
            gui_log("System", "Proxy Engine Stopped. Ready to reload.", "WARNING")

    async def run_srv(self, config, ip):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setblocking(False)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((config["LISTEN_HOST"], config["LISTEN_PORT"]))
            self.server_socket.listen()
        except Exception as e:
            gui_log("System", f"Bind Error (Port {config['LISTEN_PORT']} in use?)", "ERROR")
            return

        loop = asyncio.get_running_loop()
        while async_loop_running:
            try:
                client, addr = await loop.sock_accept(self.server_socket)
                asyncio.create_task(self.handle_client(client, addr, config, ip))
            except Exception as e:
                if async_loop_running: await asyncio.sleep(0.1)

    async def handle_client(self, client, addr, config, interface_ip):
        cid = f"{addr[0]}:{addr[1]}"
        gui_log("Client", f"New request from {cid}", "INFO")
        try:
            loop = asyncio.get_running_loop()
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out_sock.setblocking(False)
            out_sock.bind((interface_ip, 0))
            
            f_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), config["FAKE_SNI"].encode(), os.urandom(32))
            
            if "FakeInjectiveConnection" in globals():
                conn = FakeInjectiveConnection(out_sock, interface_ip, config["CONNECT_IP"], out_sock.getsockname()[1], config["CONNECT_PORT"], f_data, "wrong_seq", client)
                fake_injective_connections[conn.id] = conn
            
            gui_log("Proxy", f"[{cid}] TCP Tunneling to {config['CONNECT_IP']}...", "INFO")
            await asyncio.wait_for(loop.sock_connect(out_sock, (config["CONNECT_IP"], config["CONNECT_PORT"])), 5)
            gui_log("Proxy", f"[{cid}] Connected! Spoofing SNI...", "SUCCESS")

            # حل مشکل قطعی اتصال با گذر هوشمند از خطای تایم‌اوت DPI
            if "FakeInjectiveConnection" in globals():
                try:
                    await asyncio.wait_for(conn.t2a_event.wait(), 2)
                except asyncio.TimeoutError:
                    gui_log("DPI", f"[{cid}] Handshake timeout bypassed. Continuing relay...", "WARNING")
                conn.monitor = False
            
            gui_log("Relay", f"[{cid}] Tunnel successfully established. Transmitting data ⚡", "SUCCESS")
            
            task = asyncio.create_task(self.relay(out_sock, client, asyncio.current_task()))
            await self.relay(client, out_sock, task)
        except Exception as e:
            gui_log("Proxy", f"[{cid}] Connection terminated.", "ERROR")
        finally:
            if 'conn' in locals() and "FakeInjectiveConnection" in globals(): 
                fake_injective_connections.pop(conn.id, None)
            try: out_sock.close()
            except: pass
            try: client.close()
            except: pass

    async def relay(self, s1, s2, peer):
        try:
            loop = asyncio.get_running_loop()
            while async_loop_running:
                data = await loop.sock_recv(s1, 65575)
                if not data: break
                await loop.sock_sendall(s2, data)
        except: pass
        finally:
            if peer and not peer.done(): peer.cancel()
            try: s1.close()
            except: pass
            try: s2.close()
            except: pass

if __name__ == "__main__":
    ModernProxyGUI().mainloop()
