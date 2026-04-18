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

# تنظیمات تم مدرن
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# =====================================================================
# دیتابیس آفلاین + سیستم تشخیص هوشمند DNS
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

# امضاهای دی‌ان‌اس برای زمانی که آی‌پی در دیتابیس بالا نیست
DNS_SIGNATURES = {
    "amazonaws.com": "📦 Amazon AWS (DNS)",
    "digitalocean.com": "💧 DigitalOcean (DNS)",
    "vultr.com": "🦅 Vultr (DNS)",
    "hetzner.com": "🇩🇪 Hetzner (DNS)",
    "linode.com": "🟢 Linode/Akamai (DNS)",
    "googleusercontent.com": "🔍 Google Cloud (DNS)",
    "arvancloud": "⚡ ArvanCloud (DNS)",
    "cloudflare.com": "☁️ Cloudflare (DNS)",
    "fastly.net": "🚀 Fastly (DNS)"
}

def detect_provider(ip_str):
    # مرحله اول: جستجوی فوق‌سریع در دیتابیس استاتیک
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for provider, ranges in IP_DATABASE.items():
            for subnet in ranges:
                if ip_obj in ipaddress.ip_network(subnet): 
                    return provider
    except: pass

    # مرحله دوم: هوش مصنوعی Reverse DNS برای آی‌پی‌های ناشناخته
    try:
        # گرفتن نام دامنه اصلی سرور از طریق آی‌پی
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        hostname = hostname.lower()
        
        # بررسی امضاها در نام دامنه
        for sig, name in DNS_SIGNATURES.items():
            if sig in hostname:
                return name
                
        # اگر نام دامنه پیدا شد اما جزو شرکت‌های معروف نبود، خود نام را نشان بده
        # برای جلوگیری از طولانی شدن، فقط دو بخش آخر دامنه را نشان می‌دهیم
        parts = hostname.split('.')
        short_host = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        return f"🌐 {short_host} (DNS)"
        
    except socket.herror:
        # اگر سرور اصلاً سیستم Reverse DNS نداشت
        return "❓ Unknown (No PTR)"
    except Exception:
        return "❌ Invalid"

# =====================================================================
# ابزارهای سیستمی و اسکنر
# =====================================================================
def get_exe_dir():
    if getattr(sys, 'frozen', False): return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_ping(ip):
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(['ping', '-n', '1', '-w', '700', ip], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        stdout, _ = process.communicate()
        out = stdout.decode('cp1252')
        if "Average =" in out:
            return int(out.split("Average =")[-1].strip().replace("ms", ""))
        return 999
    except: return 999

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

# =====================================================================
# رابط کاربری v3.1 - Ultimate Analyzer Edition
# =====================================================================
log_queue = queue.Queue()
async_loop_running = False
fake_injective_connections = {}

try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
except: pass

def gui_log(source, message, level="INFO"):
    icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "Scanner": "🔍"}
    icon = icons.get(level if level in icons else source, "🔹")
    log_queue.put((time.strftime("%H:%M:%S"), level, source, f"{icon} {message}"))

class ModernProxyGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SNI Ultimate Analyzer & Proxy v3.1")
        self.geometry("1250x750")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="🧠 AI PROXY CORE", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        self.btn_scan = ctk.CTkButton(self.sidebar, text="🔍 SMART BATCH TEST", fg_color="#3498db", hover_color="#2980b9", height=40, command=self.start_bulk_scan)
        self.btn_scan.grid(row=1, column=0, padx=20, pady=10)
        
        self.info_lbl = ctk.CTkLabel(self.sidebar, text="Uses Static DB + DNS PTR\nto detect server identity.", font=ctk.CTkFont(size=11), text_color="#7f8c8d")
        self.info_lbl.grid(row=2, column=0, padx=20, pady=5)

        self.btn_toggle = ctk.CTkButton(self.sidebar, text="▶️ START PROXY", fg_color="#2ecc71", hover_color="#27ae60", height=55, font=ctk.CTkFont(size=14, weight="bold"), command=self.toggle_proxy)
        self.btn_toggle.grid(row=5, column=0, padx=20, pady=30, sticky="s")

        # Main Workspace
        self.main_work = ctk.CTkFrame(self, corner_radius=15, fg_color="#141414")
        self.main_work.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_work.grid_rowconfigure(1, weight=1)
        self.main_work.grid_columnconfigure(0, weight=1)

        # Scanner Table
        ctk.CTkLabel(self.main_work, text="📊 Dynamic Infrastructure Analysis", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="#ecf0f1", fieldbackground="#1a1a1a", rowheight=35, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#2d3436", foreground="white", relief="flat", font=("Segoe UI", 10, "bold"))

        columns = ("sni", "ip", "provider", "ping", "status")
        self.scan_tree = ttk.Treeview(self.main_work, columns=columns, show='headings', height=10)
        self.scan_tree.heading("sni", text="DOMAIN (SNI)")
        self.scan_tree.heading("ip", text="RESOLVED IP")
        self.scan_tree.heading("provider", text="DETECTED INFRASTRUCTURE")
        self.scan_tree.heading("ping", text="LATENCY")
        self.scan_tree.heading("status", text="QUALITY")
        
        self.scan_tree.column("sni", width=220)
        self.scan_tree.column("ip", width=140, anchor="center")
        self.scan_tree.column("provider", width=220, anchor="w") # عریض‌تر برای نام‌های DNS
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

    def start_bulk_scan(self):
        self.btn_scan.configure(state="disabled", text="Analyzing DNS...")
        for i in self.scan_tree.get_children(): self.scan_tree.delete(i)
        
        def run():
            path = os.path.join(get_exe_dir(), "sni_list.txt")
            if not os.path.exists(path):
                with open(path, "w") as f: f.write("auth.vercel.com\ndiscord.com\nspeedtest.net")
            
            with open(path, "r") as f: snis = [l.strip() for l in f if l.strip()]
            
            gui_log("Scanner", f"Starting deep DNS analysis for {len(snis)} nodes...", "INFO")
            
            for sni in snis:
                try:
                    ip = socket.gethostbyname(sni)
                    provider = detect_provider(ip) # استفاده از سیستم جدید دو مرحله‌ای
                    ping = get_ping(ip)
                    
                    quality = "🟢 EXCELLENT" if ping < 150 else "🟡 STABLE"
                    if ping > 400: quality = "🟠 SLOW"
                    if ping == 999: quality = "🔴 DEAD"
                    
                    self.scan_tree.insert("", tk.END, values=(sni, ip, provider, f"{ping}ms" if ping < 999 else "---", quality))
                except:
                    self.scan_tree.insert("", tk.END, values=(sni, "Unresolved", "Unknown", "---", "🚫 BLOCKED"))
            
            gui_log("Scanner", "Deep Analysis Complete.", "SUCCESS")
            self.btn_scan.configure(state="normal", text="🔍 SMART BATCH TEST")

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
            gui_log("Config", f"Activated: {sni} -> {prov}", "SUCCESS")
        except: gui_log("Config", "Failed to update config.json", "ERROR")

    def update_logs(self):
        while not log_queue.empty():
            t, l, s, m = log_queue.get()
            self.log_tree.insert("", 0, values=(t, l, s, m))
        self.after(100, self.update_logs)

    def toggle_proxy(self):
        global async_loop_running
        if not async_loop_running:
            async_loop_running = True
            self.btn_toggle.configure(text="🛑 STOP ENGINE", fg_color="#e74c3c")
            
            # --- هسته پروکسی اینجا قرار میگیرد (مشابه نسخه های قبل) ---
            gui_log("System", "Engine Engaged. Waiting for traffic...", "SUCCESS")
        else: os._exit(0)

if __name__ == "__main__":
    ModernProxyGUI().mainloop()
