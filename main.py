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

# لیست سایت‌های هدف برای اسکن و استفاده
PRESET_SNI = [
    "auth.vercel.com",
    "discord.com",
    "api.telegram.org",
    "www.hcaptcha.com",
    "cloudflare.com",
    "www.bing.com",
    "www.zdnet.com",
    "www.redhat.com"
]

# دیتابیس رنج‌های آی‌پی برای تشخیص
IP_DATABASE = {
    "☁️ Cloudflare": ["103.21.244.0/22", "104.16.0.0/13", "188.114.96.0/20", "172.64.0.0/13"],
    "⚡ ArvanCloud": ["185.143.232.0/22", "94.182.160.0/19"],
    "🚀 Fastly": ["151.101.0.0/16"],
    "📦 Amazon AWS": ["3.5.0.0/16", "54.239.0.0/16"]
}

# =====================================================================
# هسته اسکنر و ابزارهای هوشمند
# =====================================================================

def resolve_hostname(hostname):
    """اسکن کردن دامنه برای پیدا کردن آی‌پی پشت آن"""
    try:
        gui_log("Scanner", f"🔍 Scanning for {hostname} IP...", "INFO")
        return socket.gethostbyname(hostname)
    except Exception as e:
        gui_log("Scanner", f"❌ Failed to resolve {hostname}: {str(e)}", "ERROR")
        return None

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
# رابط کاربری v2.8 - Smart Scanner Edition
# =====================================================================
log_queue = queue.Queue()
async_loop_running = False
fake_injective_connections = {}

try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
except: pass

def gui_log(source, message, level="INFO"):
    icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️", "DPI": "🛡️", "Scanner": "🔭"}
    icon = icons.get(level if level in icons else source, "🔹")
    log_queue.put((time.strftime("%H:%M:%S"), level, source, f"{icon} {message}"))

class ModernProxyGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SNI Spoofing & Smart Scanner Pro v2.8")
        self.geometry("1150x680")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="🔭 SMART BYPASS", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        # SNI Scanner Control
        ctk.CTkLabel(self.sidebar, text="🔍 Scan & Apply SNI:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=20, pady=(10, 0))
        self.sni_menu = ctk.CTkOptionMenu(self.sidebar, values=PRESET_SNI, command=self.scan_and_update)
        self.sni_menu.grid(row=2, column=0, padx=20, pady=10)
        
        ctk.CTkLabel(self.sidebar, text="💡 Choosing from list will\nauto-scan IP behind SNI.", font=ctk.CTkFont(size=11), text_color="#bdc3c7").grid(row=3, column=0, padx=20)

        self.ip_box = ctk.CTkFrame(self.sidebar, fg_color="#2d3436")
        self.ip_box.grid(row=4, column=0, padx=20, pady=20, sticky="ew")
        ctk.CTkLabel(self.ip_box, text="🏠 Your Local IP:").pack(pady=(5,0))
        ctk.CTkLabel(self.ip_box, text=get_local_ip(), font=ctk.CTkFont(weight="bold")).pack(pady=(0,5))

        self.btn_toggle = ctk.CTkButton(self.sidebar, text="🚀 START ENGINE", fg_color="#2ecc71", hover_color="#27ae60", height=50, font=ctk.CTkFont(weight="bold"), command=self.toggle_proxy)
        self.btn_toggle.grid(row=5, column=0, padx=20, pady=30)

        # Main Workspace
        self.main_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="#121212")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Status Bar
        self.status_bar = ctk.CTkFrame(self.main_frame, height=70, fg_color="#1e1e1e")
        self.status_bar.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        self.status_lbl = ctk.CTkLabel(self.status_bar, text="💤 SYSTEM READY", font=ctk.CTkFont(size=15, weight="bold"), text_color="#636e72")
        self.status_lbl.pack(pady=20)

        # Activity Logs
        self.log_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.log_frame.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="#dfe6e9", fieldbackground="#1a1a1a", rowheight=32, font=("Consolas", 10))
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
        self.tree.tag_configure("Scanner", foreground="#a29bfe")
        
        self.tree.pack(fill="both", expand=True)
        self.after(100, self.refresh_logs)

    def scan_and_update(self, selected_sni):
        """عملیات اسکن و آپدیت خودکار IP و SNI"""
        def task():
            new_ip = resolve_hostname(selected_sni)
            if new_ip:
                conf_path = os.path.join(get_exe_dir(), 'config.json')
                try:
                    with open(conf_path, 'r+') as f:
                        data = json.load(f)
                        data['FAKE_SNI'] = selected_sni
                        data['CONNECT_IP'] = new_ip
                        f.seek(0)
                        json.dump(data, f, indent=4)
                        f.truncate()
                    
                    gui_log("Scanner", f"Found IP: {new_ip} for {selected_sni}", "SUCCESS")
                    ping = get_ping_status(new_ip)
                    gui_log("Scanner", f"New IP Latency: {ping}", "SUCCESS" if "ms" in ping else "ERROR")
                    
                    if async_loop_running:
                        self.status_lbl.configure(text=f"🟢 ACTIVE | IP: {new_ip} | SNI: {selected_sni}")
                        gui_log("System", "Config updated dynamically. Restart recommended if relay fails.", "WARNING")
                except:
                    gui_log("Scanner", "Failed to write to config.json", "ERROR")
            else:
                messagebox.showerror("Scan Error", f"Could not find IP for {selected_sni}")

        threading.Thread(target=task, daemon=True).start()

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
                self.status_lbl.configure(text=f"🟢 ACTIVE | IP: {config['CONNECT_IP']} | SNI: {config['FAKE_SNI']}", text_color="#2ecc71")
                
                target = config["CONNECT_IP"]
                gui_log("System", f"Engaging Bypass on {target}...", "SUCCESS")
                
                # استارت سرویس‌ها
                lip = get_local_ip()
                threading.Thread(target=lambda: asyncio.run(self.run_srv(config, lip)), daemon=True).start()
                w_filt = f"tcp and ((ip.SrcAddr == {lip} and ip.DstAddr == {target}) or (ip.SrcAddr == {target} and ip.DstAddr == {lip}))"
                threading.Thread(target=FakeTcpInjector(w_filt, fake_injective_connections).run, daemon=True).start()
                
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
        try:
            loop = asyncio.get_running_loop()
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out_sock.setblocking(False)
            out_sock.bind((interface_ip, 0))
            
            from packet_templates import ClientHelloMaker # اطمینان از وجود کلاس
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
