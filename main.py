import asyncio
import os
import socket
import struct
import sys
import traceback
import threading
import json

from fake_tcp import FakeInjectiveConnection, FakeTcpInjector

# =====================================================================
# کدهای فایل‌های network_tools و packet_templates
# مستقیما اینجا قرار گرفتند تا خطای پیدا نشدن ماژول برای همیشه ریشه کن شود
# =====================================================================

def get_default_interface_ipv4(addr="8.8.8.8") -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 53))
    except OSError:
        return ""
    else:
        return s.getsockname()[0]
    finally:
        s.close()

class ClientHelloMaker:
    tls_ch_template_str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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
# هسته اصلی برنامه
# =====================================================================

def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

config_path = os.path.join(get_exe_dir(), 'config.json')
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    sys.exit("Error: config.json not found! Please place it next to the executable.")

LISTEN_HOST = config.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = config.get("LISTEN_PORT", 40443)
FAKE_SNI = config.get("FAKE_SNI", "auth.vercel.com").encode()
CONNECT_IP = config.get("CONNECT_IP", "188.114.98.0")
CONNECT_PORT = config.get("CONNECT_PORT", 443)

INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}

async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task, first_prefix_data: bytes):
    try:
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.sock_recv(sock_1, 65575)
            if not data:
                break
            
            if first_prefix_data:
                data = first_prefix_data + data
                first_prefix_data = b""
                
            await loop.sock_sendall(sock_2, data)
            
    except asyncio.CancelledError:
        pass
    except ConnectionResetError:
        pass
    except Exception:
        pass
    finally:
        if peer_task and not peer_task.done():
            peer_task.cancel()
            
        try:
            sock_1.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock_2.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
            
        sock_1.close()
        sock_2.close()

async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    fake_injective_conn = None
    try:
        loop = asyncio.get_running_loop()
        
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI, os.urandom(32))
        else:
            sys.exit("impossible mode!")
            
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        
        try:
            outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except AttributeError:
            pass 
            
        src_port = outgoing_sock.getsockname()[1]
        
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT, fake_data, BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        
        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            return 

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    return
                if fake_injective_conn
