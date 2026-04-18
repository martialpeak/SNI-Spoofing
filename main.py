import asyncio
import os
import socket
import sys
import traceback
import threading
import json

from network_tools import get_default_interface_ipv4
from packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector

def get_exe_dir():
    """پیدا کردن مسیر اصلی برنامه برای خواندن فایل کانفیگ در کنار فایل exe"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

# خواندن فایل config.json
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
                if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                    sys.exit("impossible t2a msg!")
            except asyncio.TimeoutError:
                return 
        else:
            sys.exit("unknown bypass method!")

        fake_injective_conn.monitor = False

        oti_task = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception:
        traceback.print_exc()
    finally:
        if fake_injective_conn:
            fake_injective_conn.monitor = False
            fake_injective_connections.pop(fake_injective_conn.id, None)
        
        try:
            outgoing_sock.close()
        except: pass
        try:
            incoming_sock.close()
        except: pass

async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    
    try:
        mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except AttributeError:
        pass

    mother_sock.listen()
    print(f"Proxy is running on {LISTEN_HOST}:{LISTEN_PORT}...")
    print(f"Target: {CONNECT_IP}:{CONNECT_PORT} | SNI: {FAKE_SNI.decode()}")
    print("Waiting for connections...")
    
    loop = asyncio.get_running_loop()
    
    while True:
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            
            try:
                incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
                incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
                incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except AttributeError:
                pass
                
            asyncio.create_task(handle(incoming_sock, addr))
        except Exception:
            continue

if __name__ == "__main__":
    if not INTERFACE_IPV4:
        sys.exit("Error: Could not determine default IPv4 interface. Check your internet connection.")
        
    w_filter = "tcp and " + "(" + "(ip.SrcAddr == " + INTERFACE_IPV4 + " and ip.DstAddr == " + CONNECT_IP + ")" + " or " + "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + INTERFACE_IPV4 + ")" + ")"
    
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nبرنامه با موفقیت متوقف شد.")
