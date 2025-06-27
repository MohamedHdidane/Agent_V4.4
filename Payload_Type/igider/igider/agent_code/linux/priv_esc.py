    import pwd
    import grp
    def priv_esc(self, task_id, **kwargs):
            results = []

            # Initialize internal state similar to PrivEscEnumerator
            current_user = getpass.getuser()
            current_uid = os.getuid()
            current_gid = os.getgid()

            # Helper method to log results with severity and timestamp
            def log_result(check_name, result, severity="info"):
                results.append({
                    "check": check_name,
                    "result": result,
                    "severity": severity,
                    "timestamp": datetime.now().isoformat()
                })
            log_result("system_info", f"User: {current_user}, UID: {current_uid}, GID: {current_gid}", "info")

            # Helper method to run commands safely
            def run_command(cmd, timeout=15, shell=False):
                try:
                    if isinstance(cmd, str) and not shell:
                        cmd = cmd.split()
                    result = subprocess.run(
                        cmd, 
                        capture_output=True, 
                        text=True, 
                        timeout=timeout,
                        shell=shell
                    )
                    return result.stdout, result.stderr, result.returncode
                except subprocess.TimeoutExpired:
                    return "", "Command timed out", -1
                except FileNotFoundError:
                    return "", "Command not found", -1
                except Exception as e:
                    return "", str(e), -1

            # Check sudo privileges and dangerous configurations
            try:
                stdout, stderr, returncode = run_command(["sudo", "-l", "-n"])
                if returncode == 0:
                    log_result("sudo_privileges", f"Passwordless sudo access detected:\n{stdout}", "high")
                    dangerous_patterns = [
                        r'\(ALL\) ALL', "Full sudo access without restrictions",
                        r'\(ALL\) NOPASSWD: ALL', "Passwordless full sudo access",
                        r'NOPASSWD:.*/(sh|bash|zsh|fish|dash)', "Passwordless shell access",
                        r'NOPASSWD:.*/(vi|vim|nano|emacs|less|more)', "Passwordless editor access",
                        r'NOPASSWD:.*/(python|python3|perl|ruby|node)', "Passwordless interpreter access",
                        r'NOPASSWD:.*/systemctl', "Passwordless systemctl access",
                        r'NOPASSWD:.*/mount', "Passwordless mount access",
                        r'NOPASSWD:.*/find', "Passwordless find access",
                        r'NOPASSWD:.*/cp', "Passwordless copy access",
                        r'NOPASSWD:.*/mv', "Passwordless move access"
                    ]
                    for pattern, description in zip(dangerous_patterns[::2], dangerous_patterns[1::2]):
                        if re.search(pattern, stdout, re.IGNORECASE):
                            log_result("dangerous_sudo", f"{description}: {pattern}", "critical")
                else:
                    stdout, stderr, returncode = run_command(["sudo", "-l"])
                    if returncode == 0:
                        log_result("sudo_privileges", "Sudo access available (password required)", "medium")
                    else:
                        log_result("sudo_privileges", "No sudo privileges detected", "info")
                
                # Check privileged groups
                user_groups = [g.gr_name for g in grp.getgrall() if current_user in g.gr_mem]
                primary_group = grp.getgrgid(current_gid).gr_name
                all_groups = set(user_groups + [primary_group])
                privileged_groups = ['sudo', 'wheel', 'admin', 'root', 'adm', 'lxd', 'docker', 'disk']
                found_groups = [g for g in all_groups if g in privileged_groups]
                if found_groups:
                    severity = "critical" if "root" in found_groups else "high"
                    log_result("privileged_groups", f"User in privileged groups: {', '.join(found_groups)}", severity)
            except Exception as e:
                log_result("sudo_privileges", f"Error checking sudo: {str(e)}", "error")

            # Check critical file permissions
            critical_files = {
                "/etc/passwd": "World-writable passwd file",
                "/etc/shadow": "World-readable/writable shadow file",
                "/etc/sudoers": "World-writable sudoers file",
                "/etc/crontab": "World-writable crontab",
                "/etc/hosts": "World-writable hosts file",
                "/etc/ssh/sshd_config": "World-writable SSH config",
                "/root/.ssh/authorized_keys": "Accessible root SSH keys",
                "/etc/group": "World-writable group file",
                "/etc/gshadow": "World-readable/writable gshadow file",
                "/etc/fstab": "World-writable fstab",
                "/boot/grub/grub.cfg": "World-writable GRUB config"
            }
            try:
                for file_path, description in critical_files.items():
                    if not os.path.exists(file_path):
                        continue
                    file_stat = os.stat(file_path)
                    mode = file_stat.st_mode
                    if mode & stat.S_IWOTH:
                        log_result("file_permissions", f"{description}: {file_path}", "critical")
                    elif mode & stat.S_IWGRP:
                        try:
                            group_name = grp.getgrgid(file_stat.st_gid).gr_name
                            if group_name not in ['root', 'wheel', 'admin', 'shadow']:
                                log_result("file_permissions", f"Group-writable by {group_name}: {file_path}", "high")
                        except KeyError:
                            pass
                    sensitive_files = ["/etc/shadow", "/etc/gshadow", "/root/.ssh/authorized_keys"]
                    if file_path in sensitive_files and os.access(file_path, os.R_OK):
                        log_result("file_permissions", f"Readable sensitive file: {file_path}", "high")
            except Exception as e:
                log_result("file_permissions", f"Error checking file permissions: {str(e)}", "error")

            # Check SUID/SGID binaries
            search_paths = ["/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin", "/usr/local/sbin", "/opt/*/bin", "/snap/*/bin", "/usr/games"]
            known_safe = {
                "sudo", "su", "passwd", "chsh", "chfn", "gpasswd", "mount", "umount",
                "newgrp", "pkexec", "sg", "fusermount", "fusermount3", "sudoedit",
                "pppd", "ping", "ping6", "traceroute", "traceroute6", "ssh-keysign",
                "Xorg", "at", "crontab", "wall", "write", "chage", "expiry"
            }
            dangerous_suid = {
                "vim", "vi", "nano", "emacs", "python", "python3", "perl", "ruby",
                "sh", "bash", "zsh", "fish", "awk", "gawk", "find", "less", "more",
                "tail", "head", "sort", "uniq", "xxd", "tar", "zip", "unzip", "wget",
                "curl", "nc", "netcat", "socat", "nmap", "strace", "gdb", "node", "php"
            }
            try:
                found_binaries = []
                for path in search_paths:
                    for expanded_path in glob.glob(path):
                        if not os.path.exists(expanded_path):
                            continue
                        stdout, stderr, returncode = run_command(
                            f"find {expanded_path} -type f -perm -4000 2>/dev/null", shell=True
                        )
                        if returncode == 0 and stdout.strip():
                            for line in stdout.splitlines():
                                file_path = line.strip()
                                bin_name = os.path.basename(file_path)
                                severity = "critical" if bin_name in dangerous_suid else "medium"
                                if bin_name not in known_safe or os.access(file_path, os.W_OK):
                                    severity = "critical" if os.access(file_path, os.W_OK) else severity
                                    found_binaries.append((file_path, "SUID", severity, bin_name))
                        stdout, stderr, returncode = run_command(
                            f"find {expanded_path} -type f -perm -2000 2>/dev/null", shell=True
                        )
                        if returncode == 0 and stdout.strip():
                            for line in stdout.splitlines():
                                file_path = line.strip()
                                found_binaries.append((file_path, "SGID", "medium", os.path.basename(file_path)))
                if found_binaries:
                    for binary, bit_type, severity, bin_name in found_binaries:
                        log_result("suid_sgid_binaries", f"{bit_type} binary: {binary} ({bin_name})", severity)
                else:
                    log_result("suid_sgid_binaries", "No suspicious SUID/SGID binaries found", "info")
            except Exception as e:
                log_result("suid_sgid_binaries", f"Error checking SUID/SGID binaries: {str(e)}", "error")

            # Check file capabilities
            try:
                stdout, stderr, returncode = run_command(["which", "getcap"])
                if returncode != 0:
                    log_result("capabilities", "getcap not available", "info")
                else:
                    search_paths = ["/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"]
                    for path in search_paths:
                        if os.path.exists(path):
                            stdout, stderr, returncode = run_command(["getcap", "-r", path])
                            if returncode == 0 and stdout.strip():
                                dangerous_caps = ["cap_setuid", "cap_setgid", "cap_dac_override", "cap_sys_admin"]
                                lines = stdout.strip().split('\n')
                                for line in lines:
                                    severity = "high" if any(cap in line.lower() for cap in dangerous_caps) else "medium"
                                    log_result("capabilities", f"File with capabilities: {line}", severity)
            except Exception as e:
                log_result("capabilities", f"Error checking capabilities: {str(e)}", "error")

            # Check kernel version and vulnerabilities
            try:
                kernel_version = platform.release()
                vulnerability_checks = [
                    (r'^2\.6\.([0-9]|[1-3][0-9])($|\.)', "Very old kernel - multiple critical vulnerabilities", "critical"),
                    (r'^3\.[0-9]\.', "Old kernel - likely vulnerable to multiple exploits", "high"),
                    (r'^4\.[0-9]\.', "Older kernel - check for specific CVEs", "medium"),
                    (r'^5\.[0-3]\.', "Potentially vulnerable to recent exploits", "medium")
                ]
                for pattern, description, severity in vulnerability_checks:
                    if re.match(pattern, kernel_version):
                        log_result("kernel_version", f"{description}: {kernel_version}", severity)
                        break
                else:
                    log_result("kernel_version", f"Kernel version: {kernel_version}", "info")
                
                # Dirty COW check
                try:
                    version_match = re.match(r'^(\d+)\.(\d+)\.(\d+)', kernel_version)
                    if version_match:
                        major, minor, patch = map(int, version_match.groups())
                        if (major < 4 or 
                            (major == 4 and minor < 4) or
                            (major == 4 and minor == 4 and patch < 26) or
                            (major == 4 and minor == 7 and patch < 9) or
                            (major == 4 and minor == 8 and patch < 3)):
                            log_result("dirty_cow", f"Kernel may be vulnerable to Dirty COW (CVE-2016-5195): {kernel_version}", "high")
                except (ValueError, IndexError):
                    pass
                
                # Additional kernel vulnerabilities
                other_vulns = [
                    (r'^[23]\.', "CVE-2009-1185 (udev)", "high"),
                    (r'^4\.[0-8]\.', "Potential privilege escalation vulnerabilities", "medium")
                ]
                for pattern, vuln_desc, severity in other_vulns:
                    if re.match(pattern, kernel_version):
                        log_result("kernel_vulnerabilities", vuln_desc, severity)
            except Exception as e:
                log_result("kernel_version", f"Error checking kernel: {str(e)}", "error")

            # Check cron permissions
            cron_locations = [
                "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                "/etc/cron.monthly", "/etc/cron.weekly", "/etc/crontab",
                "/var/spool/cron", "/var/spool/cron/crontabs", "/var/cron/tabs"
            ]
            try:
                for location in cron_locations:
                    if not os.path.exists(location):
                        continue
                    if os.access(location, os.W_OK):
                        log_result("cron_permissions", f"Writable cron location: {location}", "high")
                    if os.path.isdir(location):
                        for root, dirs, files in os.walk(location):
                            for file in files:
                                file_path = os.path.join(root, file)
                                if os.access(file_path, os.W_OK):
                                    log_result("cron_permissions", f"Writable cron file: {file_path}", "high")
                                try:
                                    stat_info = os.stat(file_path)
                                    if stat_info.st_uid == current_uid:
                                        log_result("cron_permissions", f"User-owned cron file: {file_path}", "medium")
                                except:
                                    pass
            except Exception as e:
                log_result("cron_permissions", f"Error checking cron: {str(e)}", "error")

            # Check environment variables
            dangerous_env_vars = {
                "LD_PRELOAD": "Library preloading possible",
                "LD_LIBRARY_PATH": "Library path manipulation possible",
                "PATH": "PATH manipulation check",
                "PYTHONPATH": "Python path manipulation possible",
                "PERL5LIB": "Perl library manipulation possible",
                "NODE_PATH": "Node.js path manipulation possible",
                "RUBYLIB": "Ruby library manipulation possible",
                "CLASSPATH": "Java classpath manipulation possible"
            }
            try:
                for var_name, description in dangerous_env_vars.items():
                    if var_name not in os.environ:
                        continue
                    value = os.environ[var_name]
                    if var_name == "PATH":
                        writable_paths = []
                        current_dir_in_path = False
                        for path in value.split(':'):
                            if not path or path == '.':
                                current_dir_in_path = True
                                continue
                            if os.path.exists(path) and os.access(path, os.W_OK):
                                writable_paths.append(path)
                        if current_dir_in_path:
                            log_result("environment_vars", "Current directory (.) in PATH - command injection risk", "high")
                        if writable_paths:
                            log_result("environment_vars", f"Writable directories in PATH: {', '.join(writable_paths)}", "high")
                    else:
                        severity = "high" if var_name in ["LD_PRELOAD", "LD_LIBRARY_PATH"] else "medium"
                        log_result("environment_vars", f"{description}: {var_name}={value}", severity)
            except Exception as e:
                log_result("environment_vars", f"Error checking environment: {str(e)}", "error")

            # Check process information
            try:
                stdout, stderr, returncode = run_command(["ps", "aux"])
                if returncode == 0:
                    root_processes = []
                    for line in stdout.split('\n')[1:]:
                        if line.strip() and line.split()[0] == 'root':
                            process_info = ' '.join(line.split()[10:])
                            if any(service in process_info.lower() for service in ['mysql', 'postgres', 'apache', 'nginx', 'ssh']):
                                root_processes.append(process_info)
                    if root_processes:
                        log_result("root_processes", f"Services running as root:\n" + '\n'.join(root_processes[:10]), "medium")
            except Exception as e:
                log_result("process_information", f"Error checking processes: {str(e)}", "error")

            # Check network services
            try:
                for cmd in [["netstat", "-tlnp"], ["ss", "-tlnp"]]:
                    stdout, stderr, returncode = run_command(cmd)
                    if returncode == 0:
                        listening_services = []
                        for line in stdout.split('\n'):
                            if 'LISTEN' in line:
                                parts = line.split()
                                if len(parts) >= 4:
                                    address = parts[3] if cmd[0] == "netstat" else parts[4]
                                    if address.startswith('0.0.0.0:') or address.startswith(':::'):
                                        port = address.split(':')[-1]
                                        listening_services.append(f"{address} (port {port})")
                        if listening_services:
                            log_result("network_services", f"Services listening on all interfaces: {', '.join(listening_services[:10])}", "medium")
                        break
                else:
                    log_result("network_services", "Neither netstat nor ss available", "info")
            except Exception as e:
                log_result("network_services", f"Error checking network services: {str(e)}", "error")

            # Check world-writable files
            search_dirs = ["/etc", "/usr/local", "/opt", "/var", "/tmp"]
            try:
                for search_dir in search_dirs:
                    if os.path.exists(search_dir):
                        stdout, stderr, returncode = run_command(
                            f"find {search_dir} -type f -perm -002 -ls 2>/dev/null | head -20", 
                            timeout=30, shell=True
                        )
                        if returncode == 0 and stdout.strip():
                            files = stdout.strip().split('\n')
                            severity = "high" if search_dir in ["/etc", "/usr"] else "medium"
                            log_result("world_writable", f"World-writable files in {search_dir} (showing first 20):\n" + '\n'.join(files), severity)
            except Exception as e:
                log_result("world_writable", f"Error checking world-writable: {str(e)}", "error")

            # Check SSH keys
            try:
                key_patterns = [
                    "~/.ssh/id_*", "~/.ssh/*_rsa", "~/.ssh/*_dsa", "~/.ssh/*_ecdsa", "~/.ssh/*_ed25519",
                    "/home/*/.ssh/id_*", "/root/.ssh/id_*"
                ]
                for key_pattern in key_patterns:
                    for key_file in glob.glob(os.path.expanduser(key_pattern)):
                        if os.path.exists(key_file) and not key_file.endswith('.pub'):
                            if os.access(key_file, os.R_OK):
                                severity = "critical" if "/root/" in key_file else "high"
                                log_result("ssh_keys", f"Accessible private key: {key_file}", severity)
                auth_patterns = ["~/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys", "/root/.ssh/authorized_keys"]
                for auth_pattern in auth_patterns:
                    for auth_file in glob.glob(os.path.expanduser(auth_pattern)):
                        if os.access(auth_file, os.W_OK):
                            severity = "critical" if "/root/" in auth_file else "high"
                            log_result("ssh_keys", f"Writable authorized_keys: {auth_file}", severity)
                sock = os.getenv("SSH_AUTH_SOCK")
                if sock and os.path.exists(sock):
                    log_result("ssh_keys", f"SSH agent socket found: {sock}", "info")
            except Exception as e:
                log_result("ssh_keys", f"Error checking SSH keys: {str(e)}", "error")

            # Check Docker socket
            try:
                docker_sockets = ["/var/run/docker.sock", "/run/docker.sock"]
                for socket_path in docker_sockets:
                    if not os.path.exists(socket_path):
                        continue
                    if os.access(socket_path, os.R_OK | os.W_OK):
                        log_result("docker_socket", f"Docker socket is accessible: {socket_path} - Full container escape possible!", "critical")
                    elif os.access(socket_path, os.R_OK):
                        log_result("docker_socket", f"Docker socket is readable: {socket_path}", "high")
                    stat_info = os.stat(socket_path)
                    try:
                        group_name = grp.getgrgid(stat_info.st_gid).gr_name
                        user_groups = [g.gr_name for g in grp.getgrall() if current_user in g.gr_mem]
                        if group_name in user_groups:
                            log_result("docker_socket", f"User in docker group for {socket_path} - container escape possible!", "critical")
                    except:
                        pass
            except Exception as e:
                log_result("docker_socket", f"Error checking Docker socket: {str(e)}", "error")

            # Check NFS/SSHFS mounts
            try:
                stdout, stderr, returncode = run_command(["mount"])
                if returncode == 0 and ("nfs" in stdout or "sshfs" in stdout):
                    log_result("mounts", "NFS/SSHFS mounts detected. Check permissions.", "medium")
            except Exception as e:
                log_result("mounts", f"Error checking mounts: {str(e)}", "error")

            # Prepare response
            data = {
                "action": "post_response",
                "responses": [
                    {
                        "task_id": task_id,
                        "priv_esc": {
                            "results": results
                        }
                    }
                ]
            }
            initial_response = self.postMessageAndRetrieveResponse(data)
            return json.dumps({"status": "completed", "results": results})
