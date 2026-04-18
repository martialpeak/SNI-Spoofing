async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    fake_injective_conn = None
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
        
        # اعمال تنظیمات سوکت به صورت امن
        try:
            outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except AttributeError:
            pass # سیستم از این فلگ‌ها پشتیبانی نمی‌کند
            
        src_port = outgoing_sock.getsockname()[1]
        
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        
        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            return # رفتن به بلاک finally

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    return
                if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                    sys.exit("impossible t2a msg!")
            except asyncio.TimeoutError:
                return # رفتن به بلاک finally
        else:
            sys.exit("unknown bypass method!")

        # متوقف کردن مانیتور پس از انجام عملیات
        fake_injective_conn.monitor = False

        # اجرای حلقه‌های رله دوطرفه
        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception:
        traceback.print_exc()
    finally:
        # پاکسازی تضمینی حافظه و سوکت‌ها تحت هر شرایطی
        if fake_injective_conn:
            fake_injective_conn.monitor = False
            fake_injective_connections.pop(fake_injective_conn.id, None)
        
        try:
            outgoing_sock.close()
        except: pass
        try:
            incoming_sock.close()
        except: pass
