    def validate_target(target):
        """Validate IP address, CIDR, or hostname"""
        try:
            # Check if it's an IP address or CIDR
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                return True
            else:
                ipaddress.ip_address(target)
                return True
        except ValueError:
            # Check if it's a valid hostname
            hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            if re.match(hostname_pattern, target) and len(target) <= 253:
                return True
            return False

    def build_nuclei_command(target, templates="", severity="", timeout=300):
        """Build nuclei command with validation"""
        cmd = ["nuclei", "-target", target, "-json", "-silent", "-no-color"]
        
        # Add template filtering
        if templates:
            template_list = [t.strip() for t in templates.split(',')]
            # Validate template tags (basic validation)
            valid_templates = []
            for template in template_list:
                if re.match(r'^[a-zA-Z0-9\-_]+$', template):
                    valid_templates.append(template)
            
            if valid_templates:
                cmd.extend(["-tags", ",".join(valid_templates)])
        
        # Add severity filtering
        valid_severities = ["info", "low", "medium", "high", "critical"]
        if severity and severity.lower() in valid_severities:
            cmd.extend(["-severity", severity.lower()])
        
        return cmd, int(timeout)

    def parse_nuclei_output(stdout):
        """Parse nuclei JSON output and format for display"""
        if not stdout.strip():
            return "✅ Nuclei scan completed - No vulnerabilities found", []
        
        findings = []
        for line in stdout.strip().split('\n'):
            if line:
                try:
                    finding = json.loads(line)
                    parsed_finding = {
                        'template_id': finding.get('template-id', 'unknown'),
                        'template_name': finding.get('info', {}).get('name', 'Unknown'),
                        'severity': finding.get('info', {}).get('severity', 'unknown'),
                        'host': finding.get('host', ''),
                        'matched_at': finding.get('matched-at', ''),
                        'description': finding.get('info', {}).get('description', ''),
                        'reference': finding.get('info', {}).get('reference', []),
                        'tags': finding.get('info', {}).get('tags', [])
                    }
                    findings.append(parsed_finding)
                except json.JSONDecodeError:
                    # Skip malformed JSON lines
                    continue
        
        if not findings:
            return "✅ Nuclei scan completed - No vulnerabilities found", []
        
        # Format output
        output = f"🔍 Nuclei scan completed - {len(findings)} finding(s):\n\n"
        
        # Group findings by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        findings_by_severity = {}
        
        for finding in findings:
            severity = finding['severity'].lower()
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)
        
        # Display findings ordered by severity
        for severity in severity_order:
            if severity in findings_by_severity:
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🟠', 
                    'medium': '🟡',
                    'low': '🔵',
                    'info': '⚪'
                }.get(severity, '⚫')
                
                output += f"{severity_emoji} {severity.upper()} SEVERITY ({len(findings_by_severity[severity])} finding(s)):\n"
                
                for finding in findings_by_severity[severity]:
                    output += f"  [{finding['template_id']}] {finding['template_name']}\n"
                    output += f"    Host: {finding['host']}\n"
                    if finding['matched_at']:
                        output += f"    Matched: {finding['matched_at']}\n"
                    if finding['description']:
                        desc = finding['description'][:150] + "..." if len(finding['description']) > 150 else finding['description']
                        output += f"    Description: {desc}\n"
                    if finding['reference']:
                        refs = finding['reference'][:2]  # Show max 2 references
                        output += f"    References: {', '.join(refs)}\n"
                    output += "\n"
        
        return output, findings

    def nuclei(self, task_id, target, templates="", severity="", timeout=300):
        """Execute nuclei scan from Mythic server"""
        
        # Validate target
        if not validate_target(target):
            error_msg = f"[!] Invalid target format: {target}"
            data = {
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": error_msg,
                    "completed": True,
                    "status": "error"
                }]
            }
            self.postMessageAndRetrieveResponse(data)
            return error_msg
        
        # Build command
        try:
            cmd, scan_timeout = build_nuclei_command(target, templates, severity, timeout)
        except Exception as e:
            error_msg = f"[!] Failed to build nuclei command: {str(e)}"
            data = {
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": error_msg,
                    "completed": True,
                    "status": "error"
                }]
            }
            self.postMessageAndRetrieveResponse(data)
            return error_msg
        
        # Send initial response
        scan_params = f"Target: {target}"
        if templates:
            scan_params += f", Templates: {templates}"
        if severity:
            scan_params += f", Severity: {severity}"
        
        initial_msg = f"🚀 Starting nuclei scan...\n{scan_params}\nTimeout: {scan_timeout}s"
        
        data = {
            "action": "post_response",
            "responses": [{
                "task_id": task_id,
                "user_output": initial_msg,
                "completed": False
            }]
        }
        self.postMessageAndRetrieveResponse(data)
        
        # Execute nuclei scan
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=scan_timeout,
                text=True,
                cwd="/tmp"  # Run from safe directory
            )
            
            if result.returncode != 0 and result.stderr:
                error_output = result.stderr[:500]  # Limit error output
                error_msg = f"[!] Nuclei scan failed:\n{error_output}"
                
                data = {
                    "action": "post_response", 
                    "responses": [{
                        "task_id": task_id,
                        "user_output": error_msg,
                        "completed": True,
                        "status": "error"
                    }]
                }
                self.postMessageAndRetrieveResponse(data)
                return error_msg
            
            # Parse and format output
            formatted_output, findings = parse_nuclei_output(result.stdout)
            
            # Send final response
            data = {
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": formatted_output,
                    "completed": True,
                    "status": "success"
                }]
            }
            self.postMessageAndRetrieveResponse(data)
            
            return f"Nuclei scan completed for {target}. Found {len(findings)} vulnerabilities."
            
        except subprocess.TimeoutExpired:
            timeout_msg = f"[!] Nuclei scan timed out after {scan_timeout} seconds"
            data = {
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": timeout_msg,
                    "completed": True,
                    "status": "error"
                }]
            }
            self.postMessageAndRetrieveResponse(data)
            return timeout_msg
            
        except FileNotFoundError:
            error_msg = "[!] Nuclei binary not found on Mythic server. Please install nuclei first."
            data = {
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": error_msg,
                    "completed": True,
                    "status": "error"
                }]
            }
            self.postMessageAndRetrieveResponse(data)
            return error_msg
            
        except Exception as e:
            error_msg = f"[!] Unexpected error during nuclei scan: {str(e)}"
            data = {
                "action": "post_response",
                "responses": [{
                    "task_id": task_id,
                    "user_output": error_msg,
                    "completed": True,
                    "status": "error"
                }]
            }
            self.postMessageAndRetrieveResponse(data)
            return error_msg