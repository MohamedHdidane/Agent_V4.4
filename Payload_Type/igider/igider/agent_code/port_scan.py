    import socket
    import threading
    import json
    from datetime import datetime

    def port_scan(self, task_id, target, ports, timeout=1, threads=100):
        """
        Perform port scan on target host(s) with specified ports
        """
        try:
            timeout = float(timeout)     
            threads = int(threads)         
            # Parse target - can be single IP or IP range
            targets = self._parse_targets(target)
            port_list = self._parse_ports(ports)
            
            if not targets:
                return json.dumps({"error": "Invalid target specified"})
            
            if not port_list:
                return json.dumps({"error": "Invalid ports specified"})
            
            # Initialize results
            scan_results = {
                "scan_start": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "targets": targets,
                "ports": port_list,
                "results": {},
                "summary": {"total_hosts": len(targets), "total_ports": len(port_list)}
            }
            
            # Perform scan for each target
            for target_ip in targets:
                if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                    scan_results["status"] = "stopped"
                    break
                    
                scan_results["results"][target_ip] = self._scan_host(target_ip, port_list, timeout, threads, task_id)
                
                # Send intermediate results
                self._send_intermediate_results(task_id, target_ip, scan_results["results"][target_ip])
            
            scan_results["scan_end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return json.dumps(scan_results)
            
        except Exception as e:
            return json.dumps({"error": f"Port scan failed: {str(e)}"})

    def _parse_targets(self, target):
        """Parse target specification into list of IPs"""
        targets = []
        
        if "-" in target:
            # IP range like 192.168.1.1-192.168.1.10
            start_ip, end_ip = target.split("-")
            start_parts = start_ip.split(".")
            end_parts = end_ip.split(".")
            
            if len(start_parts) == 4 and len(end_parts) == 4:
                start_last = int(start_parts[3])
                end_last = int(end_parts[3])
                base_ip = ".".join(start_parts[:3])
                
                for i in range(start_last, end_last + 1):
                    targets.append(f"{base_ip}.{i}")
        elif "/" in target:
            # CIDR notation like 192.168.1.0/24
            import ipaddress
            network = ipaddress.IPv4Network(target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        else:
            # Single IP
            targets = [target]
        
        return targets

    def _parse_ports(self, ports):
        """Parse port specification into list of ports"""
        port_list = []
        
        if isinstance(ports, str):
            port_ranges = ports.split(",")
            for port_range in port_ranges:
                port_range = port_range.strip()
                if "-" in port_range:
                    start_port, end_port = map(int, port_range.split("-"))
                    port_list.extend(range(start_port, end_port + 1))
                else:
                    port_list.append(int(port_range))
        elif isinstance(ports, list):
            port_list = ports
        
        return sorted(list(set(port_list)))  # Remove duplicates and sort

    def _scan_host(self, target_ip, port_list, timeout, max_threads, task_id):
        """Scan all ports on a single host using threading"""
        open_ports = []
        closed_ports = []
        filtered_ports = []
        
        # Semaphore to limit concurrent threads
        semaphore = threading.Semaphore(max_threads)
        threads = []
        results_lock = threading.Lock()
        
        def scan_port(ip, port):
            semaphore.acquire()
            try:
                # Check if task was stopped
                if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                    return
                    
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                with results_lock:
                    if result == 0:
                        # Try to get service info
                        service = self._get_service_name(port)
                        open_ports.append({"port": port, "service": service, "state": "open"})
                    else:
                        closed_ports.append({"port": port, "state": "closed"})
                        
            except socket.timeout:
                with results_lock:
                    filtered_ports.append({"port": port, "state": "filtered"})
            except Exception:
                with results_lock:
                    filtered_ports.append({"port": port, "state": "filtered"})
            finally:
                semaphore.release()
        
        # Create and start threads
        for port in port_list:
            if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                break
                
            thread = threading.Thread(target=scan_port, args=(target_ip, port))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        return {
            "host": target_ip,
            "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            "closed_ports": len(closed_ports),
            "filtered_ports": len(filtered_ports),
            "total_scanned": len(port_list)
        }

    def _get_service_name(self, port):
        """Get common service name for port"""
        common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 443: "https", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy"
        }
        return common_ports.get(port, "unknown")

    def _send_intermediate_results(self, task_id, target, results):
        """Send intermediate scan results"""
        data = {
            "action": "post_response",
            "responses": [{
                "task_id": task_id,
                "user_output": f"Completed scan for {target}: {len(results['open_ports'])} open ports found",
                "completed": False
            }]
        }
        self.postMessageAndRetrieveResponse(data)