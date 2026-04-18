import asyncio
import os
import socket
import struct
import sys
import traceback
import threading
import json
import queue
import time
import tkinter as tk
from tkinter import ttk, font, messagebox

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
# هسته پروکسی
# =====================================================================
log_queue = queue.Queue()

def gui_log(source, message, level="INFO"):
    log_queue.put((time.strftime("%H:%M:%S"), level, source, message))

def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}
async_loop_running = False

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
    except: pass
    finally:
        if peer_task and not peer_task.done(): peer_task.cancel()
        try: sock_1.shutdown(socket.SHUT_RDWR)
        except: pass
        try: sock_2.shutdown(socket.SHUT_RDWR)
        except: pass
        sock_1.close()
        sock_2.close()

async def handle(incoming_sock: socket.socket, addr, config: dict, interface_ip: str):
    fake_injective_conn = None
    gui_log("Client", f"New Connection from {addr[0]}:{addr[1]}")
    
    try:
        loop = asyncio.get_running_loop()
        connect_ip = config.get("CONNECT_IP")
        connect_port = config.get("CONNECT_PORT")
        fake_sni = config.get("FAKE_SNI", "").encode()
        
        fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), fake_sni, os.urandom(32))
        
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((interface_ip, 0))
        
        src_port = outgoing_sock.getsockname()[1]
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, interface_ip, connect_ip, src_port, connect_port, fake_data, "wrong_seq", incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        
        gui_log("Proxy", f"Connecting to Target: {connect_ip}...")
        
        try:
            await asyncio.wait_for(loop.sock_connect(outgoing_sock, (connect_ip, connect_port)), timeout=5)
            gui_log("Proxy", "Connection to Target Successful.", "SUCCESS")
        except Exception as e:
            gui_log("Proxy", f"Failed to connect to Target: {str(e)}", "ERROR")
            return 

        try:
            await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
            if fake_injective_conn.t2a_msg == "unexpected_close": 
                gui_log("DPI", "Unexpected Close during handshake", "WARNING")
                return
        except asyncio.TimeoutError:
            gui_log("DPI", "Handshake timeout", "WARNING")
            return 

        fake_injective_conn.monitor = False
        gui_log("Relay", "Tunnel established. Relaying data...")
        
        oti_task = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception as e:
        gui_log("System", f"Handle Error: {str(e)}", "ERROR")
    finally:
        if fake_injective_conn:
            fake_injective_conn.monitor = False
            fake_injective_connections.pop(fake_injective_conn.id, None)
        try: outgoing_sock.close()
        except: pass
        try: incoming_sock.close()
        except: pass
        gui_log("Client", f"Connection {addr[0]} Closed.")

async def run_proxy_server(config, interface_ip):
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((config.get("LISTEN_HOST", "0.0.0.0"), config.get("LISTEN_PORT", 40443)))
    mother_sock.listen()
    
    gui_log("System", "Proxy Server initialized.")
    
    loop = asyncio.get_running_loop()
    while async_loop_running:
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            asyncio.create_task(handle(incoming_sock, addr, config, interface_ip))
        except:
            await asyncio.sleep(0.1)

# =====================================================================
# رابط کاربری گرافیکی مدرن
# =====================================================================
class ProxyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SNI Spoofing Proxy V2")
        self.root.geometry("800x500")
        self.root.configure(bg="#2b2b2b")
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#1e1e1e", foreground="white", fieldbackground="#1e1e1e", rowheight=25)
        style.map("Treeview", background=[('selected', '#3a3a3a')])
        
        # Main Layout
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top Panel: Info and Control
        top_panel = ttk.LabelFrame(main_frame, text=" Server Information ", padding="10")
        top_panel.pack(fill=tk.X, pady=(0, 10))
        
        self.info_text = tk.StringVar(value="Status: Not Running | Target: None")
        ttk.Label(top_panel, textvariable=self.info_text, font=("Segoe UI", 10)).pack(side=tk.LEFT)
        
        self.btn_toggle = ttk.Button(top_panel, text="Start Proxy", command=self.toggle_proxy)
        self.btn_toggle.pack(side=tk.RIGHT)
        
        # Bottom Panel: Tabular Logs
        log_frame = ttk.LabelFrame(main_frame, text=" Activity Logs ", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("time", "level", "source", "message")
        self.tree = ttk.Treeview(log_frame, columns=columns, show='headings')
        self.tree.heading("time", text="Time")
        self.tree.heading("level", text="Level")
        self.tree.heading("source", text="Source")
        self.tree.heading("message", text="Message")
        
        self.tree.column("time", width=80, anchor=tk.CENTER)
        self.tree.column("level", width=80, anchor=tk.CENTER)
        self.tree.column("source", width=100, anchor=tk.CENTER)
        self.tree.column("message", width=450)
        
        # Tags for Colors
        self.tree.tag_configure("ERROR", foreground="#ff6b6b")
        self.tree.tag_configure("SUCCESS", foreground="#51cf66")
        self.tree.tag_configure("WARNING", foreground="#fcc419")
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.root.after(100, self.process_logs)

    def process_logs(self):
        while not log_queue.empty():
            t, level, src, msg = log_queue.get()
            self.tree.insert("", tk.END, values=(t, level, src, msg), tags=(level,))
            self.tree.yview_moveto(1)
        self.root.after(100, self.process_logs)

    def toggle_proxy(self):
        global async_loop_running
        if not async_loop_running:
            config_path = os.path.join(get_exe_dir(), 'config.json')
            try:
                with open(config_path, 'r') as f: config = json.load(f)
                interface_ip = get_default_interface_ipv4(config['CONNECT_IP'])
                
                async_loop_running = True
                self.btn_toggle.config(text="Stop Proxy")
                self.info_text.set(f"Running on {config['LISTEN_PORT']} | Target: {config['CONNECT_IP']}")
                
                # Background threads
                threading.Thread(target=lambda: asyncio.run(run_proxy_server(config, interface_ip)), daemon=True).start()
                w_filter = f"tcp and ((ip.SrcAddr == {interface_ip} and ip.DstAddr == {config['CONNECT_IP']}) or (ip.SrcAddr == {config['CONNECT_IP']} and ip.DstAddr == {interface_ip}))"
                threading.Thread(target=FakeTcpInjector(w_filter, fake_injective_connections).run, daemon=True).start()
                
                gui_log("System", "All services started successfully.", "SUCCESS")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            async_loop_running = False
            os._exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = ProxyGUI(root)
    root.mainloop()
