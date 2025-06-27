from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json

class SocksArguments(TaskArguments):

    valid_actions = ["start", "stop", "status"]

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action", 
                choices=["start", "stop", "status"], 
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )], 
                type=ParameterType.ChooseOne, 
                description="Start, stop, or check status of the SOCKS server."
            ),
            CommandParameter(
                name="port", 
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )], 
                type=ParameterType.Number, 
                description="Port to start the SOCKS server on (default: 7005)."
            ),
            CommandParameter(
                name="interface", 
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )], 
                type=ParameterType.String, 
                description="Network interface to bind to (optional)."
            ),
            CommandParameter(
                name="max_connections", 
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )], 
                type=ParameterType.Number, 
                description="Maximum number of concurrent connections (default: 300)."
            ),
        ]

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must specify an action: start, stop, or status")
        
        try:
            self.load_args_from_json_string(self.command_line)
        except:
            parts = self.command_line.lower().split()
            action = parts[0]
            
            if action not in self.valid_actions:
                raise Exception(f"Invalid action '{action}'. Valid actions: {', '.join(self.valid_actions)}")
            
            self.add_arg("action", action)
            
            if action == "start":
                # Default port
                port = 7005
                max_connections = 300
                interface = ""
                
                # Parse additional parameters
                i = 1
                while i < len(parts):
                    if parts[i].isdigit():
                        port = int(parts[i])
                    elif parts[i].startswith("max="):
                        max_connections = int(parts[i].split("=")[1])
                    elif parts[i].startswith("interface="):
                        interface = parts[i].split("=")[1]
                    i += 1
                
                self.add_arg("port", port, ParameterType.Number)
                self.add_arg("max_connections", max_connections, ParameterType.Number)
                self.add_arg("interface", interface, ParameterType.String)


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks [start|stop|status] [port] [max=N] [interface=eth0]"
    description = """
    Enhanced SOCKS5 proxy with connection pooling, batching, and performance optimizations.
    
    Features:
    - Connection pooling for improved performance
    - Packet batching for reduced overhead
    - IPv6 support
    - Real-time statistics
    - Automatic cleanup of stale connections
    - Configurable buffer sizes and connection limits
    
    Examples:
    socks start 1080                    # Start on port 1080
    socks start 1080 max=500           # Start with max 500 connections
    socks start 1080 interface=eth0    # Bind to specific interface
    socks status                       # Show current status
    socks stop                         # Stop the proxy
    """
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@ajpc500 (enhanced)"
    argument_class = SocksArguments
    attackmapping = ["T1090", "T1090.001", "T1090.002"]
    attributes = CommandAttributes(
        supported_python_versions=["Python 3.8", "Python 3.9", "Python 3.10", "Python 3.11"],
        supported_os=[SupportedOS.MacOS, SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        action = taskData.args.get_arg("action")
        
        if action == "start":
            port = taskData.args.get_arg("port") or 7005
            max_connections = taskData.args.get_arg("max_connections") or 300
            interface = taskData.args.get_arg("interface") or ""
            
            resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                LocalPort=port
            ))

            if not resp.Success:
                response.TaskStatus = MythicStatus.Error
                response.Stderr = resp.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=resp.Error.encode()
                ))
            else:
                display_params = f"Enhanced SOCKS5 server on port {port}"
                if max_connections != 300:
                    display_params += f" (max {max_connections} connections)"
                if interface:
                    display_params += f" on interface {interface}"
                response.DisplayParams = display_params
                
        elif action == "stop":
            port = taskData.args.get_arg("port")
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                Port=port
            ))
            
            if not resp.Success:
                response.TaskStatus = MythicStatus.Error
                response.Stderr = resp.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=resp.Error.encode()
                ))
            else:
                response.DisplayParams = "Stopped Enhanced SOCKS5 server"
                
        elif action == "status":
            response.DisplayParams = "Checking SOCKS5 server status"
            
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp