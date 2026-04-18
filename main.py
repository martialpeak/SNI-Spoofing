import asyncio
import os
import socket
import struct
import sys
import threading
import json
import queue
import time
import subprocess
import ipaddress
import customtkinter as ctk
from tkinter import ttk, messagebox

# تنظیمات تم ظاهری
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# =====================================================================
# دیتابیس آفلاین رنج‌های آی‌پی برای تشخیص سرویس‌دهنده
# =====================================================================
IP_DATABASE = {
    "Cloudflare": ["103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"],
    "ArvanCloud": ["185.143.232.0/22", "94.182.160.0/19", "185.17.112.0/22", "185.176.4.0/22"],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "Amazon AWS": ["3.5.0.0/16", "52.95.0.0/16", "54.239.0.0/16"],
    "Google Cloud": ["34.0.0.0/8", "35.0.0.0/8"]
}

def detect_provider(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for provider, ranges in IP_DATABASE.items():
            for subnet in ranges:
                if ip_obj in ipaddress.ip_network(subnet):
                    return provider
        return "Unknown Provider"
    except:
        return "Invalid IP"

def get_ping_status(ip):
    try:
        # ارسال ۱ پکت پینگ با تایم‌اوت ۱ ثانیه در ویندوز
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(['ping', '-n', '1', '-w', '1000', ip], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        stdout, stderr = process.communicate()
        out = stdout.decode('cp1252')
        if "Average =" in out:
            ms = out.split("Average =")[-1].strip().replace("ms", "")
            return f"{ms}ms"
        return "Timeout"
    except:
        return "Offline"

# =====================================================================
# ابزارهای سیستم و لاگ
# =====================================================================
def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

LOG_FILE_PATH = os.path.join(get_exe_dir(), "debug.log")

if os.path.exists(LOG_FILE_PATH):
    try: os.remove(LOG_FILE_PATH)
    except: pass

def write_to_log_file(msg):
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

# =====================================================================
# هسته پروکسی (ترکیب شده با WinDivert)
# =====================================================================
try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
except ImportError:
    pass # در صورتی که فایل‌های جانبی نباشند (در بیلد اصلی مشکلی نخواهد بود)

log_queue = queue.Queue()
async_loop_running = False
fake_injective_connections = {}

def gui_log(source, message, level="INFO"):
    entry = (time.strftime("%H:%M:%S"), level, source, message)
    log_queue.put(entry)
    write_to_log_file(f"[{level}] {source}: {message}")

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
# رابط کاربری فوق مدرن
# =====================================================================
class ModernProxyGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SNI Spoofing Pro v2.6")
        self.geometry("1000x620")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar Panel
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_lbl = ctk.CTkLabel(self.sidebar, text="SNI BYPASS", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_lbl.grid(row=0, column=0, padx=20, pady=(40, 30))
        
        self.local_ip_box = ctk.CTkFrame(self.sidebar, fg_color="#2c3e50")
        self.local_ip_box.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        ctk.CTkLabel(self.local_ip_box, text="Your Local IP (Sharing):").pack(pady=(10, 0))
        ctk.CTkLabel(self.local_ip_box, text=get_local_ip(), font=ctk.CTkFont(weight="bold")).pack(pady=(0, 10))

        self.btn_toggle = ctk.CTkButton(self.sidebar, text="START ENGINE", fg_color="#2ecc71", hover_color="#27ae60", height=50, font=ctk.CTkFont(size=14, weight="bold"), command=self.toggle_proxy)
        self.btn_toggle.grid(row=2, column=0, padx=20, pady=40)

        # Main Workspace
        self.main_work = ctk.CTkFrame(self, corner_radius=15, fg_color="#121212")
        self.main_work.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_work.grid_rowconfigure(1, weight=1)
        self.main_work.grid_columnconfigure(0, weight=1)

        # Header Info Card
        self.header_card = ctk.CTkFrame(self.main_work, height=80, fg_color="#1e1e1e")
        self.header_card.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        
        self.status_text = ctk.CTkLabel(self.header_card, text="SYSTEM READY - STANDBY", font=ctk.CTkFont(size=16, weight="bold"), text_color="#7f8c8d")
        self.status_text.pack(expand=True)

        # Modern Log Table
        self.log_container = ctk.CTkFrame(self.main_work, fg_color="transparent")
        self.log_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1e1e1e", foreground="#ecf0f1", fieldbackground="#1e1e1e", borderwidth=0, font=("Consolas", 10), rowheight=30)
        style.configure("Treeview.Heading", background="#2d3436", foreground="white", relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[('selected', '#3498db')])

        self.tree = ttk.Treeview(self.log_container, columns=("T", "L", "S", "M"), show='headings')
        self.tree.heading("T", text="TIMESTAMP")
        self.tree.heading("L", text="LEVEL")
        self.tree.heading("S", text="SOURCE")
        self.tree.heading("M", text="MESSAGE")
        
        self.tree.column("T", width=100, anchor="center")
        self.tree.column("L", width=100, anchor="center")
        self.tree.column("S", width=120, anchor="center")
        self.tree.column("M", width=500)
        
        self.tree.tag_configure("ERROR", foreground="#e74c3c")
        self.tree.tag_configure("SUCCESS", foreground="#2ecc71")
        self.tree.tag_configure("WARNING", foreground="#f1c40f")
        
        self.tree.pack(fill="both", expand=True)
        
        self.after(100, self.update_table)

    def update_table(self):
        while not log_queue.empty():
            t, l, s, m = log_queue.get()
            self.tree.insert("", 0, values=(t, l, s, m), tags=(l,))
        self.after(100, self.update_table)

    def toggle_proxy(self):
        global async_loop_running
        if not async_loop_running:
            try:
                conf_path = os.path.join(get_exe_dir(), 'config.json')
                with open(conf_path) as f: config = json.load(f)
                
                target_ip = config["CONNECT_IP"]
                async_loop_running = True
                self.btn_toggle.configure(text="STOP ENGINE", fg_color="#e74c3c", hover_color="#c0392b")
                self.status_text.configure(text=f"CONNECTED: {target_ip}", text_color="#2ecc71")
                
                # --- بخش هوشمند جدید ---
                gui_log("Analyzer", f"Analyzing Target: {target_ip}...")
                provider = detect_provider(target_ip)
                ping_val = get_ping_status(target_ip)
                
                gui_log("Analyzer", f"Provider Detected: {provider}", "SUCCESS" if provider != "Unknown Provider" else "INFO")
                gui_log("Analyzer", f"Ping Latency: {ping_val}", "SUCCESS" if ping_val != "Offline" else "ERROR")
                
                if ping_val == "Offline":
                    messagebox.showwarning("Connection Alert", f"Warning: The IP {target_ip} seems to be offline or unreachable!")
                # -----------------------

                local_ip = get_local_ip()
                threading.Thread(target=lambda: asyncio.run(self.run_srv(config, local_ip)), daemon=True).start()
                
                w_filter = f"tcp and ((ip.SrcAddr == {local_ip} and ip.DstAddr == {target_ip}) or (ip.SrcAddr == {target_ip} and ip.DstAddr == {local_ip}))"
                threading.Thread(target=FakeTcpInjector(w_filter, fake_injective_connections).run, daemon=True).start()
                
                gui_log("System", "Bypass Engine Engaged.", "SUCCESS")
            except Exception as e: messagebox.showerror("Fatal Error", f"Config load failed: {str(e)}")
        else: os._exit(0)

    async def run_srv(self, config, ip):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setblocking(False)
        srv.bind((config["LISTEN_HOST"], config["LISTEN_PORT"]))
        srv.listen()
        loop = asyncio.get_running_loop()
        while async_loop_running:
            client, addr = await loop.sock_accept(srv)
            asyncio.create_task(self.handle_client(client, addr, config, ip))

    async def handle_client(self, client, addr, config, interface_ip):
        try:
            loop = asyncio.get_running_loop()
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out_sock.setblocking(False)
            out_sock.bind((interface_ip, 0))
            
            f_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), config["FAKE_SNI"].encode(), os.urandom(32))
            conn = FakeInjectiveConnection(out_sock, interface_ip, config["CONNECT_IP"], out_sock.getsockname()[1], config["CONNECT_PORT"], f_data, "wrong_seq", client)
            fake_injective_connections[conn.id] = conn
            
            await asyncio.wait_for(loop.sock_connect(out_sock, (config["CONNECT_IP"], config["CONNECT_PORT"])), 5)
            await asyncio.wait_for(conn.t2a_event.wait(), 2)
            conn.monitor = False
            
            task = asyncio.create_task(self.relay(out_sock, client, asyncio.current_task()))
            await self.relay(client, out_sock, task)
        except: pass
        finally:
            if 'conn' in locals(): fake_injective_connections.pop(conn.id, None)

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
            s1.close()
            s2.close()

if __name__ == "__main__":
    ModernProxyGUI().mainloop()
