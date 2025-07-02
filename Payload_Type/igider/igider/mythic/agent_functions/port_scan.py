from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *


class PortScanArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target", 
                type=ParameterType.String, 
                description="Target host/IP or IP range (e.g., 192.168.1.1, 192.168.1.1-10, 192.168.1.0/24)",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=1,
                    required=True
                )]
            ),
            CommandParameter(
                name="ports", 
                type=ParameterType.String, 
                description="Ports to scan (e.g., 80, 80-443, 21,22,80,443)",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=2,
                    required=True
                )]
            ),
            CommandParameter(
                name="timeout", 
                type=ParameterType.String, 
                description="Connection timeout in seconds (default: 1)",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=3,
                    required=False
                )],
                default_value="1"
            ),
            CommandParameter(
                name="threads", 
                type=ParameterType.String, 
                description="Maximum concurrent threads (default: 100)",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=4,
                    required=False
                )],
                default_value="100"
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require target and ports to scan.\n\tUsage: {}".format(PortScanCommand.help_cmd))
        if self.command_line[0] == "{":
            # JSON input
            temp_json = json.loads(self.command_line)
            if "target" in temp_json:
                self.add_arg("target", temp_json["target"])
            if "ports" in temp_json:
                self.add_arg("ports", temp_json["ports"])
            if "timeout" in temp_json:
                self.add_arg("timeout", str(temp_json["timeout"]))
            if "threads" in temp_json:
                self.add_arg("threads", str(temp_json["threads"]))
        else:
            # Split command line and handle quoted arguments
            parts = []
            current_part = ""
            in_quotes = False
            quote_char = None
            
            for char in self.command_line:
                if char in ['"', "'"] and not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char and in_quotes:
                    in_quotes = False
                    quote_char = None
                elif char == ' ' and not in_quotes:
                    if current_part:
                        parts.append(current_part)
                        current_part = ""
                else:
                    current_part += char
            
            if current_part:
                parts.append(current_part)
            
            if len(parts) < 2:
                raise Exception("Require both target and ports.\n\tUsage: {}".format(PortScanCommand.help_cmd))
            
            # Set parameters explicitly
            self.add_arg("target", parts[0])
            self.add_arg("ports", parts[1])

            if len(parts) > 2:
                self.add_arg("timeout", parts[2])

            if len(parts) > 3:
                self.add_arg("threads", parts[3])


class PortScanCommand(CommandBase):
    cmd = "port_scan"
    needs_admin = False
    help_cmd = "port_scan [target] [ports] [timeout] [threads]"
    description = "Perform TCP port scan on target host(s). Supports single IPs, IP ranges, and CIDR notation."
    version = 1
    supported_ui_features = []
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_remove_file = False
    is_upload_file = False
    parameters = []
    attackmapping = ["T1046"]  # Network Service Scanning
    argument_class = PortScanArguments
    browser_script = BrowserScript(script_name="port_scan", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.MacOS, SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        target = taskData.args.get_arg("target")
        ports = taskData.args.get_arg("ports")
        timeout_str = taskData.args.get_arg("timeout")
        threads_str = taskData.args.get_arg("threads")
        
        # Convert string parameters to numbers with validation
        try:
            timeout = float(timeout_str) if timeout_str else 1.0
        except (ValueError, TypeError):
            timeout = 1.0
            
        try:
            threads = int(threads_str) if threads_str else 100
        except (ValueError, TypeError):
            threads = 100
        
        response.DisplayParams = f"Target: {target}, Ports: {ports}, Timeout: {timeout}s, Threads: {threads}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp