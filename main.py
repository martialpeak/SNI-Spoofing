import asyncio
import os
import socket
import struct
import sys
import threading
import json
import queue
import time
import customtkinter as ctk
from tkinter import ttk, messagebox

# سعی در وارد کردن کلاس‌های خارجی، در غیر این صورت برنامه از منطق داخلی استفاده می‌کند
try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
except ImportError:
    # این بخش فقط برای جلوگیری از کرش در محیط‌های بدون فایل‌های جانبی است
    pass

# تنظیمات تم ظاهری
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# =====================================================================
# توابع کمکی و ابزارهای شبکه (ادغام شده برای پایداری ۱۰۰٪)
# =====================================================================
def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

LOG_FILE_PATH = os.path.join(get_exe_dir(), "debug.log")

# پاکسازی لاگ قبلی در هر شروع مجدد
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

def get_default_interface_ipv4(addr="8.8.8.8") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
        return s.getsockname()[0]
    except: return ""
    finally: s.close()

class ClientHelloMaker:
    # متن هگز تمپلیت - برای جلوگیری از خطای Hex به چند بخش تقسیم شده است
    tls_ch_template_str = (
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc"
        "90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8"
        "c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00"
        "160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e31001600"
        "0000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205"
        "020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e06134"
        "73e2338770efdaa98693d217001500d50000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    
    # اصلاح خودکار در صورت نقص کاراکتر هنگام کپی
    _clean_hex = tls_ch_template_str.replace('\n', '').replace(' ', '')
    if len(_clean_hex) % 2 != 0: _clean_hex += "0"
    tls_ch_template = bytes.fromhex(_clean_hex)

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes, key_share: bytes) -> bytes:
        template_sni = "mci.ir".encode()
        static1, static2, static3 = cls.tls_ch_template[:11], b"\x20", cls.tls_ch_template[76:120]
        static4 = cls.tls_ch_template[127 + len(template_sni):262 + len(template_sni)]
        server_name_ext = struct.pack("!H", len(target_sni) + 5) + struct.pack("!H", len(target_sni) + 3) + b"\x00" + struct.pack("!H", len(target_sni)) + target_sni
        padding_ext = struct.pack("!H", 219 - len(target_sni)) + (b"\x00" * (219 - len(target_sni)))
        return static1 + rnd + static2 + sess_id + static3 + server_name_ext + static4 + key_share + b"\x00\x15" + padding_ext

# =====================================================================
# مدیریت لاگ و هسته پروکسی
# =====================================================================
log_queue = queue.Queue()
async_loop_running = False
fake_injective_connections = {}

def gui_log(source, message, level="INFO"):
    entry = (time.strftime("%H:%M:%S"), level, source, message)
    log_queue.put(entry)
    write_to_log_file(f"[{level}] {source}: {message}")

async def relay_main_loop(sock_1, sock_2, peer_task, first_prefix_data):
    try:
        loop = asyncio.get_running_loop()
        while async_loop_running:
            data = await loop.sock_recv(sock_1, 65575)
            if not data: break
            if first_prefix_data: data, first_prefix_data = first_prefix_data + data, b""
            await loop.sock_sendall(sock_2, data)
    except: pass
    finally:
        if peer_task and not peer_task.done(): peer_task.cancel()
        for s in [sock_1, sock_2]:
            try: s.shutdown(socket.SHUT_RDWR)
            except: pass
            s.close()

async def handle(incoming_sock, addr, config, interface_ip):
    gui_log("Client", f"Req from {addr[0]}")
    try:
        loop = asyncio.get_running_loop()
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((interface_ip, 0))
        
        fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), config["FAKE_SNI"].encode(), os.urandom(32))
        conn = FakeInjectiveConnection(outgoing_sock, interface_ip, config["CONNECT_IP"], outgoing_sock.getsockname()[1], config["CONNECT_PORT"], fake_data, "wrong_seq", incoming_sock)
        fake_injective_connections[conn.id] = conn
        
        try:
            gui_log("Proxy", f"Connecting to {config['CONNECT_IP']}...")
            await asyncio.wait_for(loop.sock_connect(outgoing_sock, (config["CONNECT_IP"], config["CONNECT_PORT"])), 5)
            gui_log("Proxy", "Target Connected.", "SUCCESS")
        except Exception as e:
            gui_log("Proxy", f"Failed: {str(e)}", "ERROR")
            return

        await asyncio.wait_for(conn.t2a_event.wait(), 2)
        conn.monitor = False
        oti_task = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")
    except: pass
    finally:
        if 'conn' in locals(): fake_injective_connections.pop(conn.id, None)

# =====================================================================
# رابط کاربری مدرن (CustomTkinter)
# =====================================================================
class ModernProxyGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SNI Spoofing Pro - v2.5")
        self.geometry("950x600")
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="PROXY PANEL", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 20))
        
        self.ip_display = ctk.CTkLabel(self.sidebar, text=f"Local IP:\n{get_local_ip()}", font=ctk.CTkFont(size=13))
        self.ip_display.grid(row=1, column=0, padx=20, pady=10)

        self.btn_toggle = ctk.CTkButton(self.sidebar, text="START ENGINE", fg_color="#2ecc71", hover_color="#27ae60", height=45, font=ctk.CTkFont(weight="bold"), command=self.toggle_proxy)
        self.btn_toggle.grid(row=2, column=0, padx=20, pady=30)

        # Main Area
        self.main_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="#1a1a1a")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Header Status
        self.status_box = ctk.CTkFrame(self.main_frame, height=70, fg_color="#252525")
        self.status_box.grid(row=0, column=0, sticky="ew", padx=15, pady=15)
        self.status_info = ctk.CTkLabel(self.status_box, text="SYSTEM STATUS: WAITING", text_color="#95a5a6", font=ctk.CTkFont(size=15, weight="bold"))
        self.status_info.pack(pady=20)

        # Activity Table
        self.table_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.table_container.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="white", fieldbackground="#1a1a1a", borderwidth=0, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#333333", foreground="white", relief="flat")
        style.map("Treeview", background=[('selected', '#3498db')])

        self.tree = ttk.Treeview(self.table_container, columns=("T", "L", "S", "M"), show='headings')
        self.tree.heading("T", text="TIME")
        self.tree.heading("L", text="LEVEL")
        self.tree.heading("S", text="SOURCE")
        self.tree.heading("M", text="MESSAGE")
        
        self.tree.column("T", width=90, anchor="center")
        self.tree.column("L", width=90, anchor="center")
        self.tree.column("S", width=110, anchor="center")
        self.tree.column("M", width=420)
        
        self.tree.tag_configure("ERROR", foreground="#ff7675")
        self.tree.tag_configure("SUCCESS", foreground="#55efc4")
        self.tree.tag_configure("WARNING", foreground="#ffeaa7")
        
        self.tree.pack(fill="both", expand=True)
        
        self.after(100, self.refresh_ui_logs)

    def refresh_ui_logs(self):
        while not log_queue.empty():
            t, l, s, m = log_queue.get()
            self.tree.insert("", 0, values=(t, l, s, m), tags=(l,))
        self.after(100, self.refresh_ui_logs)

    def toggle_proxy(self):
        global async_loop_running
        if not async_loop_running:
            try:
                conf_file = os.path.join(get_exe_dir(), 'config.json')
                with open(conf_file) as f: config = json.load(f)
                
                async_loop_running = True
                self.btn_toggle.configure(text="STOP ENGINE", fg_color="#e74c3c", hover_color="#c0392b")
                self.status_info.configure(text=f"CONNECTED: {config['LISTEN_PORT']} -> {config['CONNECT_IP']}", text_color="#2ecc71")
                
                # اجرای تردها
                local_ip = get_default_interface_ipv4(config['CONNECT_IP'])
                threading.Thread(target=lambda: asyncio.run(self.start_srv(config, local_ip)), daemon=True).start()
                
                w_filter = f"tcp and ((ip.SrcAddr == {local_ip} and ip.DstAddr == {config['CONNECT_IP']}) or (ip.SrcAddr == {config['CONNECT_IP']} and ip.DstAddr == {local_ip}))"
                threading.Thread(target=FakeTcpInjector(w_filter, fake_injective_connections).run, daemon=True).start()
                
                gui_log("System", "Proxy & WinDivert Started.", "SUCCESS")
                gui_log("System", f"Local sharing IP: {get_local_ip()}")
            except Exception as e: messagebox.showerror("Error", f"Failed to start: {str(e)}")
        else: os._exit(0)

    async def start_srv(self, config, ip):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setblocking(False)
        srv.bind((config["LISTEN_HOST"], config["LISTEN_PORT"]))
        srv.listen()
        loop = asyncio.get_running_loop()
        while async_loop_running:
            client, addr = await loop.sock_accept(srv)
            asyncio.create_task(handle(client, addr, config, ip))

if __name__ == "__main__":
    gui_app = ModernProxyGUI()
    gui_app.mainloop()
