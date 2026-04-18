import asyncio
import os
import socket
import struct
import sys
import traceback
import threading
import json
import queue
import tkinter as tk
from tkinter import scrolledtext, font, messagebox

from fake_tcp import FakeInjectiveConnection, FakeTcpInjector

# =====================================================================
# توابع شبکه و پکت‌ها
# =====================================================================
def get_default_interface_ipv4(addr="8.8.8.8") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
        ip = s.getsockname()[0]
    except OSError:
        ip = ""
    finally:
        s.close()
    return ip

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
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    if len(tls_ch_template_str.replace('\n', '').replace(' ', '')) % 2 != 0:
        tls_ch_template_str += "0"
        
    tls_ch_template = bytes.fromhex(tls_ch_template_str)
    template_sni = "mci.ir".encode()
    static1 = tls_ch_template[:11]
    static2 = b"\x20"
    static3 = tls_ch_template[76:120]
    static4 = tls_ch_template[127 + len(template_sni):262 + len(template_sni)]
    static5 = b"\x00\x15"

    @classmethod
    def get_client_hello_with(cls, rnd: bytes, sess_id: bytes, target_sni: bytes, key_share: bytes) -> bytes:
        server_name_ext = struct.pack("!H", len(target_sni) + 5) + struct.pack("!H", len(target_sni) + 3) + b"\x00" + struct.pack("!H", len(target_sni)) + target_sni
        padding_ext = struct.pack("!H", 219 - len(target_sni)) + (b"\x00" * (219 - len(target_sni)))
        return cls.static1 + rnd + cls.static2 + sess_id + cls.static3 + server_name_ext + cls.static4 + key_share + cls.static5 + padding_ext

# =====================================================================
# هسته اصلی پروکسی و پردازش
# =====================================================================
def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}
async_loop_running = False
proxy_thread = None

async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task, first_prefix_data: bytes):
    try:
        loop = asyncio.get_running_loop()
        while async_loop_running:
            data = await loop.sock_recv(sock_1, 65575)
            if not data: break
            if first_prefix_data:
                data = first_prefix_data + data
                first_prefix_data = b""
            await loop.sock_sendall(sock_2, data)
    except Exception: pass
    finally:
        if peer_task and not peer_task.done(): peer_task.cancel()
        try: sock_1.shutdown(socket.SHUT_RDWR)
        except: pass
        try: sock_2.shutdown(socket.SHUT_RDWR)
        except: pass
        sock_1.close()
        sock_2.close()

async def handle(incoming_sock: socket.socket, config: dict, interface_ip: str):
    fake_injective_conn = None
    try:
        loop = asyncio.get_running_loop()
        connect_ip = config.get("CONNECT_IP")
        connect_port = config.get("CONNECT_PORT")
        fake_sni = config.get("FAKE_SNI", "").encode()
        
        fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), fake_sni, os.urandom(32))
        
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((interface_ip, 0))
        
        try:
            outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        except AttributeError: pass 
            
        src_port = outgoing_sock.getsockname()[1]
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, interface_ip, connect_ip, src_port, connect_port, fake_data, "wrong_seq", incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        
        try: await loop.sock_connect(outgoing_sock, (connect_ip, connect_port))
        except Exception: return 

        try:
            await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
            if fake_injective_conn.t2a_msg == "unexpected_close": return
        except asyncio.TimeoutError: return 

        fake_injective_conn.monitor = False
        oti_task = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception: pass
    finally:
        if fake_injective_conn:
            fake_injective_conn.monitor = False
            fake_injective_connections.pop(fake_injective_conn.id, None)
        try: outgoing_sock.close()
        except: pass
        try: incoming_sock.close()
        except: pass

async def run_proxy_server(config, interface_ip):
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((config.get("LISTEN_HOST", "0.0.0.0"), config.get("LISTEN_PORT", 40443)))
    mother_sock.listen()
    
    print(f"[*] Proxy Server Started!")
    print(f"[*] Listening on: {config.get('LISTEN_HOST')}:{config.get('LISTEN_PORT')}")
    print(f"[*] Target: {config.get('CONNECT_IP')}:{config.get('CONNECT_PORT')}")
    print(f"[*] Faking SNI: {config.get('FAKE_SNI')}")
    print("[*] Waiting for client connections...\n")
    
    loop = asyncio.get_running_loop()
    while async_loop_running:
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            print(f"[+] New connection from {addr[0]}:{addr[1]}")
            asyncio.create_task(handle(incoming_sock, config, interface_ip))
        except Exception:
            await asyncio.sleep(0.1)

def start_background_tasks(config):
    global async_loop_running
    async_loop_running = True
    interface_ip = get_default_interface_ipv4(config.get("CONNECT_IP", "8.8.8.8"))
    
    if not interface_ip:
        print("[!] Error: No internet connection found.")
        return

    # استارت WinDivert
    w_filter = f"tcp and ((ip.SrcAddr == {interface_ip} and ip.DstAddr == {config['CONNECT_IP']}) or (ip.SrcAddr == {config['CONNECT_IP']} and ip.DstAddr == {interface_ip}))"
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, daemon=True).start()
    print("[*] WinDivert Packet Injector Started.")

    # استارت سرور پروکسی
    asyncio.run(run_proxy_server(config, interface_ip))

# =====================================================================
# رابط کاربری گرافیکی (GUI) و هدایت لاگ‌ها
# =====================================================================
class RedirectText:
    """کلاسی برای انتقال لاگ‌های کنسول به داخل تکست‌باکس محیط گرافیکی (Thread-Safe)"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.log_queue = queue.Queue()
        self.update_widget()

    def write(self, string):
        self.log_queue.put(string)

    def flush(self): pass

    def update_widget(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg)
            self.text_widget.see(tk.END)
            self.text_widget.configure(state='disabled')
        self.text_widget.after(100, self.update_widget)

class ProxyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SNI Spoofing Proxy - Patterniha")
        self.root.geometry("600x450")
        self.root.configure(bg="#1E1E1E")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        custom_font = font.Font(family="Consolas", size=10)

        # Header Frame
        header_frame = tk.Frame(root, bg="#1E1E1E")
        header_frame.pack(fill=tk.X, pady=10)

        self.lbl_status = tk.Label(header_frame, text="Status: Stopped", fg="#FF5555", bg="#1E1E1E", font=("Arial", 12, "bold"))
        self.lbl_status.pack(side=tk.LEFT, padx=20)

        self.btn_start = tk.Button(header_frame, text="Start Proxy", bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=12, command=self.start_proxy)
        self.btn_start.pack(side=tk.RIGHT, padx=20)

        # Log Area
        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="#000000", fg="#00FF00", font=custom_font, state='disabled')
        self.log_area.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        # Redirect Console Output
        sys.stdout = RedirectText(self.log_area)
        sys.stderr = RedirectText(self.log_area)

        print("=== SNI Spoofing Proxy GUI ===")
        print("Ready to start. Make sure config.json is in the folder.\n")

    def start_proxy(self):
        global proxy_thread
        config_path = os.path.join(get_exe_dir(), 'config.json')
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            print("[!] Error: config.json not found next to the executable!")
            messagebox.showerror("Error", "config.json file is missing!")
            return

        self.btn_start.config(state=tk.DISABLED, text="Running...")
        self.lbl_status.config(text="Status: Running", fg="#4CAF50")
        
        # اجرای سرور در پس زمینه تا فرم گرافیکی قفل نکند
        proxy_thread = threading.Thread(target=start_background_tasks, args=(config,), daemon=True)
        proxy_thread.start()

    def on_closing(self):
        global async_loop_running
        print("Stopping services...")
        async_loop_running = False
        self.root.destroy()
        os._exit(0)  # خروج کامل و بستن تمام پردازش‌های پس‌زمینه

if __name__ == "__main__":
    app_root = tk.Tk()
    gui = ProxyGUI(app_root)
    app_root.mainloop()
