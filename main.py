import asyncio
import os
import socket
import sys
import traceback
import threading
import json

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))


# Build the path to config.json
config_path = os.path.join(get_exe_dir(), 'config.json')

# Load the config
with open(config_path, 'r') as f:
    config = json.load(f)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

##################

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                          first_prefix_data: bytes):
    """
    نسخه اصلاح شده: جلوگیری از خطای WinError 6 با بستن امن سوکت‌ها
    """
    try:
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.sock_recv(sock_1, 65575)
            if not data:
                break  # خروج امن از حلقه به جای تولید خطا
            
            if first_prefix_data:
                data = first_prefix_data + data
                first_prefix_data = b""
                
            await loop.sock_sendall(sock_2, data)
            
    except asyncio.CancelledError:
        # تسک به صورت عمدی کنسل شده است
        pass
    except ConnectionResetError:
        pass
    except Exception:
        pass
    finally:
        # ابتدا تسک همتا (peer) را کنسل می‌کنیم تا از خواندن/نوشتن همزمان جلوگیری شود
        if peer_task and not peer_task.done():
            peer_task.cancel()
            
        # شات‌دان کردن سوکت قبل از بستن کامل آن در ویندوز الزامی است
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
    try:
        loop = asyncio.get_running_loop()
        
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            sys.exit("impossible mode!")
            
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        src_port = outgoing_sock.getsockname()[1]
        
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        
        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            fake_injective_conn.monitor = False
            del fake_injective_connections[fake_injective_conn.id]
            outgoing_sock.close()
            incoming_sock.close()
            return

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    # استفاده از return به جای raise ValueError برای جلوگیری از کرش
                    return
                if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    pass
                else:
                    sys.exit("impossible t2a msg!")
            except Exception:
                fake_injective_conn.monitor = False
                if fake_injective_conn.id in fake_injective_connections:
                    del fake_injective_connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return
        else:
            sys.exit("unknown bypass method!")

        fake_injective_conn.monitor = False
        if fake_injective_conn.id in fake_injective_connections:
            del fake_injective_connections[fake_injective_conn.id]

        # اجرای حلقه‌های رله دوطرفه
        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception:
        traceback.print_exc()


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    mother_sock.listen()
    loop = asyncio.get_running_loop()
    
    while True:
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            asyncio.create_task(handle(incoming_sock, addr))
        except Exception:
            continue


if __name__ == "__main__":
    w_filter = "tcp and " + "(" + "(ip.SrcAddr == " + INTERFACE_IPV4 + " and ip.DstAddr == " + CONNECT_IP + ")" + " or " + "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + INTERFACE_IPV4 + ")" + ")"
    
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    
    print("هشن شومافر تیامح دینکیم هدافتسا دازآ تنرتنیا هب یسرتسد یارب همانرب نیا زا رگا")
    print("دراد امش تیامح هب زاین هک مراد رظن رد دازآ تنرتنیا هب ناریا مدرم مامت یسرتسد یارب یدایز یاه همانرب و اه هژورپ")
    print("\nUSDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424\n")
    print("@patterniha")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nبرنامه با موفقیت متوقف شد.")
