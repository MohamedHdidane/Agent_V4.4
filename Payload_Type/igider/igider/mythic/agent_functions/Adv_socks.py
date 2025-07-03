from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json

class Adv_socksArguments(TaskArguments):

    valid_actions = ["start", "stop"]

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action", 
                choices=["start", "stop"], 
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )], 
                type=ParameterType.ChooseOne, 
                description="Start or stop the SOCKS server."
            ),
            CommandParameter(
                name="port", 
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )], 
                type=ParameterType.Number, 
                description="Port to start the SOCKS server on (default: 7005)."
            ),
        ]

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must be passed \"start\" or \"stop\" commands on the command line.")
        try:
            self.load_args_from_json_string(self.command_line)
        except:
            parts = self.command_line.lower().split()
            action = parts[0]
            if action not in self.valid_actions:
                raise Exception("Invalid action \"{}\" given. Require one of: {}".format(action, ", ".join(self.valid_actions)))
            self.add_arg("action", action)
            if action == "start":
                port = -1
                if len(parts) < 2:
                    port = 7005
                else:
                    try:
                        port = int(parts[1])
                    except Exception as e:
                        raise Exception("Invalid port number given: {}. Must be int.".format(parts[1]))
                self.add_arg("port", port, ParameterType.Number)


class Adv_socksCommand(CommandBase):
    cmd = "Adv_socks"
    needs_admin = False
    help_cmd = "Adv_socks [start|stop] [port]"
    description = """
    Enhanced SOCKS5 proxy with connection pooling, batching, and performance optimizations.
    
    Features:
    - Connection pooling for improved performance
    - Packet batching for reduced overhead
    - IPv6 support
    - Real-time statistics
    - Automatic cleanup of stale connections
    - Optimized buffer sizes and connection handling
    
    Examples:
    Adv_socks start 1080          # Start on port 1080
    Adv_socks start               # Start on default port 7005
    Adv_socks stop                # Stop the proxy
    """
    version = 2
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@Med"
    argument_class = Adv_socksArguments
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
        
        if taskData.args.get_arg("action") == "start":
            port = taskData.args.get_arg("port") or 7005
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
                response.DisplayParams = "Started Enhanced SOCKS5 server on port {}".format(port)
        else:
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                Port=taskData.args.get_arg("port")
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
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp