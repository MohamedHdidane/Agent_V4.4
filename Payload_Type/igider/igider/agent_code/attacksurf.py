    import socket
    import ipaddress
    import json
    import threading

    TOP_COMMON_PORTS = [
        445,3389,135,139,22,80,443,8080,8443,21,25,110,143,993,995,389,636,53,3306,1433,
        1521,5432,6379,9200,27017,5900,5985,5986,8000,9090
    ]

    CHUNK_HOSTS = 25

    def enumerate_local_interfaces():
        # Simplified: return list of (ifname, ip, netmask)
        # Use psutil or netifaces if available
        return []

    def expand_auto_cidrs():
        cidrs = []
        for ifn, ip, mask in enumerate_local_interfaces():
            try:
                net = ipaddress.ip_interface(f"{ip}/{mask}").network
                if net.prefixlen < 24:
                    cidrs.append(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
                else:
                    cidrs.append(str(net))
            except:
                continue
        return list(dict.fromkeys(cidrs))

    def scan_host(host, ports, timeout, banners, http):
        open_ports = []
        for p in ports:
            s = socket.socket()
            s.settimeout(timeout)
            try:
                s.connect((host, p))
                info = {"port": p}
                if banners:
                    try:
                        s.send(b"\r\n")
                        bdat = s.recv(256)
                        if bdat:
                            info["banner"] = bdat.decode(errors="ignore").strip()
                    except:
                        pass
                if http and p in (80, 443, 8080, 8443):
                    try:
                        req = b"GET / HTTP/1.0\r\nHost: "+host.encode()+b"\r\n\r\n"
                        s.send(req)
                        resp = s.recv(512).decode(errors="ignore")
                        title = ""
                        server = ""
                        if "<title>" in resp.lower():
                            lower = resp.lower()
                            start = lower.find("<title>")
                            end = lower.find("</title>", start)
                            if end > start:
                                title = resp[start+7:end].strip()
                        for line in resp.splitlines():
                            if line.lower().startswith("server:"):
                                server = line.split(":", 1)[1].strip()
                        if title or server:
                            info["http"] = {}
                            if title: info["http"]["title"] = title
                            if server: info["http"]["server"] = server
                    except:
                        pass
                open_ports.append(info)
            except:
                pass
            finally:
                s.close()
        return {"host": host, "ports": open_ports}

    def arp_discover(cidrs):
        hosts = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts.extend([str(ip) for ip in list(net.hosts())[:32]])  # cap per network
        return hosts

    def send_chunk(post_fn, task_id, hosts_chunk, processed, total):
        data = {
            "action": "post_response",
            "responses": [{
                "task_id": task_id,
                "user_output": json.dumps({
                    "chunk": processed,
                    "total_hosts": total,
                    "hosts": hosts_chunk
                })[:8192],  # size safety
                "completed": False
            }]
        }
        post_fn(data)

    def send_summary(post_fn, task_id, total):
        data = {
            "action": "post_response",
            "responses": [{
                "task_id": task_id,
                "user_output": f"Attack surface scan complete. Hosts processed: {total}",
                "completed": True
            }]
        }
        post_fn(data)

    def attack_surface_scan(post_fn, task_id, args):
        cidrs = [c.strip() for c in args.get("cidrs", "").split(",") if c.strip()] \
                if args.get("cidrs") else expand_auto_cidrs()
        top_ports = int(args.get("top_ports", 20))
        top_list = TOP_COMMON_PORTS[:top_ports]
        timeout = int(args.get("timeout_ms", 800)) / 1000.0
        rate = int(args.get("rate", 128))
        banners = bool(args.get("banners", False))
        http = bool(args.get("http", False))
        max_hosts = int(args.get("max_hosts", 256))

        discovered_hosts = arp_discover(cidrs)
        hosts_to_scan = discovered_hosts[:max_hosts]

        results_buffer = []
        total = len(hosts_to_scan)
        processed = 0

        for host in hosts_to_scan:
            host_result = scan_host(host, top_list, timeout, banners, http)
            results_buffer.append(host_result)
            processed += 1
            if len(results_buffer) >= CHUNK_HOSTS or processed == total:
                send_chunk(post_fn, task_id, results_buffer, processed, total)
                results_buffer = []
        send_summary(post_fn, task_id, total)

    def attack_surface_arguments(command_line):
        args = {
            "cidrs": "",
            "top_ports": 20,
            "banners": False,
            "http": False,
            "timeout_ms": 800,
            "rate": 128,
            "max_hosts": 256
        }
        if command_line.startswith("{"):
            # If arguments are passed in JSON format
            temp = json.loads(command_line)
            for key, value in temp.items():
                if key in args:
                    args[key] = value
        else:
            # If it's a plain CIDR argument
            args["cidrs"] = command_line.strip()
        return args

    def attack_surface_command(command_line, post_fn, task_id):
        args = attack_surface_arguments(command_line)
        attack_surface_scan(post_fn, task_id, args)
