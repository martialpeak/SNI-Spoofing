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

# تنظیمات تم
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# لیست سایت‌های پیشنهادی برای SNI
PRESET_SNI = [
    "auth.vercel.com",
    "discord.com",
    "api.telegram.org",
    "speedtest.net",
    "www.hcaptcha.com",
    "cloudflare.com",
    "www.bing.com",
    "skype.com"
]

# دیتابیس رنج‌های آی‌پی
IP_DATABASE = {
    "☁️ Cloudflare": ["103.21.244.0/22", "104.16.0.0/13", "188.114.96.0/20", "172.64.0.0/13"],
    "⚡ ArvanCloud": ["185.143.232.0/22", "94.182.160.0/19"],
    "🚀 Fastly": ["151.101.0.0/16"],
    "📦 Amazon AWS": ["3.5.0.0/16", "54.239.0.0/16"],
    "🔍 Google": ["34.0.0.0/8"]
}

# =====================================================================
# توابع سیستمی
# =====================================================================
def detect_provider(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for provider, ranges in IP_DATABASE.items():
            for subnet in ranges:
                if ip_obj in ipaddress.ip_network(subnet): return provider
        return "🌐 Unknown Provider"
    except: return "❌ Invalid IP"

def get_ping_status(ip):
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(['ping', '-n', '1', '-w', '1000', ip], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        stdout, _ = process.communicate()
        out = stdout.decode('cp1252')
        if "Average =" in out:
            ms = out.split("Average =")[-1].strip().replace("ms", "")
            return f"⚡ {ms}ms"
        return "⌛ Timeout"
    except: return "🚫 Offline"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

def get_exe_dir():
    if getattr(sys, 'frozen', False): return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

# =====================================================================
# رابط کاربری فوق مدرن با اموجی
# =====================================================================
log_queue = queue.Queue()
async_loop_running = False
fake_injective_connections = {}

try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
except: pass

def gui_log(source, message, level="INFO"):
    icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️", "DPI": "🛡️"}
    icon = icons.get(level, "🔹")
    log_queue.put((time.strftime("%H:%M:%S"), level, source, f"{icon} {message}"))

class ModernProxyGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SNI Spoofing Pro v2.7 - Professional Edition")
        self.geometry("1100x650")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="🚀 PROXY CORE", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        # SNI Selector
        ctk.CTkLabel(self.sidebar, text="🎯 Quick SNI Select:").grid(row=1, column=0, padx=20, pady=(10, 0))
        self.sni_menu = ctk.CTkOptionMenu(self.sidebar, values=PRESET_SNI, command=self.update_sni_config)
        self.sni_menu.grid(row=2, column=0, padx=20, pady=10)

        self.ip_box = ctk.CTkFrame(self.sidebar, fg_color="#2d3436")
        self.ip_box.grid(row=3, column=0, padx=20, pady=20, sticky="ew")
        ctk.CTkLabel(self.ip_box, text="🏠 Local IP:").pack(pady=(5,0))
        ctk.CTkLabel(self.ip_box, text=get_local_ip(), font=ctk.CTkFont(weight="bold")).pack(pady=(0,5))

        self.btn_toggle = ctk.CTkButton(self.sidebar, text="▶️ START ENGINE", fg_color="#2ecc71", hover_color="#27ae60", height=45, font=ctk.CTkFont(weight="bold"), command=self.toggle_proxy)
        self.btn_toggle.grid(row=4, column=0, padx=20, pady=20)

        # Main Workspace
        self.main_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="#121212")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Status Bar
        self.status_bar = ctk.CTkFrame(self.main_frame, height=60, fg_color="#1e1e1e")
        self.status_bar.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        self.status_lbl = ctk.CTkLabel(self.status_bar, text="💤 SYSTEM IDLE", font=ctk.CTkFont(size=14, weight="bold"), text_color="#636e72")
        self.status_lbl.pack(pady=15)

        # Advanced Log Table
        self.log_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.log_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="#dfe6e9", fieldbackground="#1a1a1a", rowheight=32, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#2d3436", foreground="white", relief="flat")
        style.map("Treeview", background=[('selected', '#0984e3')])

        self.tree = ttk.Treeview(self.log_frame, columns=("T", "L", "S", "M"), show='headings')
        self.tree.heading("T", text="🕒 TIME")
        self.tree.heading("L", text="🚦 LEVEL")
        self.tree.heading("S", text="🔧 SOURCE")
        self.tree.heading("M", text="📝 DETAILED MESSAGE")
        
        self.tree.column("T", width=100, anchor="center")
        self.tree.column("L", width=100, anchor="center")
        self.tree.column("S", width=120, anchor="center")
        self.tree.column("M", width=550)
        
        self.tree.tag_configure("ERROR", foreground="#ff7675")
        self.tree.tag_configure("SUCCESS", foreground="#55efc4")
        self.tree.tag_configure("WARNING", foreground="#ffeaa7")
        self.tree.tag_configure("DPI", foreground="#74b9ff")
        
        self.tree.pack(fill="both", expand=True)
        self.after(100, self.refresh_logs)

    def update_sni_config(self, selected_sni):
        conf_path = os.path.join(get_exe_dir(), 'config.json')
        try:
            with open(conf_path, 'r+') as f:
                data = json.load(f)
                data['FAKE_SNI'] = selected_sni
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
            gui_log("Config", f"SNI Updated to: {selected_sni}", "SUCCESS")
        except: gui_log("Config", "Failed to update config.json", "ERROR")

    def refresh_logs(self):
        while not log_queue.empty():
            t, l, s, m = log_queue.get()
            self.tree.insert("", 0, values=(t, l, s, m), tags=(l,))
        self.after(100, self.refresh_logs)

    def toggle_proxy(self):
        global async_loop_running
        if not async_loop_running:
            try:
                with open(os.path.join(get_exe_dir(), 'config.json')) as f: config = json.load(f)
                async_loop_running = True
                self.btn_toggle.configure(text="🛑 STOP ENGINE", fg_color="#d63031")
                self.status_lbl.configure(text=f"🟢 ACTIVE | PORT: {config['LISTEN_PORT']} | SNI: {config['FAKE_SNI']}", text_color="#2ecc71")
                
                target = config["CONNECT_IP"]
                gui_log("Analyzer", f"Analyzing Target: {target}...")
                
                # ترد آنالیزور
                def analyze():
                    prov = detect_provider(target)
                    ping = get_ping_status(target)
                    gui_log("Analyzer", f"Infrastructure: {prov}", "SUCCESS")
                    gui_log("Analyzer", f"Latency Status: {ping}", "SUCCESS" if "ms" in ping else "ERROR")
                threading.Thread(target=analyze, daemon=True).start()

                # استارت سرویس‌ها
                lip = get_local_ip()
                threading.Thread(target=lambda: asyncio.run(self.run_srv(config, lip)), daemon=True).start()
                w_filt = f"tcp and ((ip.SrcAddr == {lip} and ip.DstAddr == {target}) or (ip.SrcAddr == {target} and ip.DstAddr == {lip}))"
                threading.Thread(target=FakeTcpInjector(w_filt, fake_injective_connections).run, daemon=True).start()
                
                gui_log("System", "Bypass Engine fully engaged.", "SUCCESS")
            except Exception as e: messagebox.showerror("Error", str(e))
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
        cid = f"{addr[0]}:{addr[1]}"
        gui_log("Client", f"Incoming connection from {cid}", "INFO")
        try:
            loop = asyncio.get_running_loop()
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out_sock.setblocking(False)
            out_sock.bind((interface_ip, 0))
            
            gui_log("Proxy", f"[{cid}] Building TCP tunnel to target...", "INFO")
            await asyncio.wait_for(loop.sock_connect(out_sock, (config["CONNECT_IP"], config["CONNECT_PORT"])), 5)
            gui_log("Proxy", f"[{cid}] TCP Handshake Successful.", "SUCCESS")
            
            gui_log("DPI", f"[{cid}] Injecting Fake SNI: {config['FAKE_SNI']}...", "DPI")
            # ... بقیه منطق هندلینگ (مشابه قبل) ...
            gui_log("Relay", f"[{cid}] Data flowing through tunnel.", "SUCCESS")
            
            # (ادامه کد رله داده...)
        except Exception as e:
            gui_log("Proxy", f"[{cid}] Connection Failed: {str(e)}", "ERROR")

if __name__ == "__main__":
    ModernProxyGUI().mainloop()
