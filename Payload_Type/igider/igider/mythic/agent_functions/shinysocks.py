from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import base64
import socket
import select
import queue
import threading
import time
import struct


class ShinySocksArguments(TaskArguments):
    """Arguments for the ShinySocks command - same structure as original SOCKS"""
    
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
                description="Start, stop, or check status of the ShinySocks server."
            ),
            CommandParameter(
                name="port", 
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )], 
                type=ParameterType.Number, 
                description="Port to start the ShinySocks server on (default: 1080)."
            ),
        ]

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must be passed \"start\", \"stop\", or \"status\" commands on the command line.")
        try:
            self.load_args_from_json_string(self.command_line)
        except:
            parts = self.command_line.lower().split()
            action = parts[0]
            if action not in self.valid_actions:
                raise Exception("Invalid action \"{}\" given. Require one of: {}".format(action, ", ".join(self.valid_actions)))
            self.add_arg("action", action)
            if action == "start":
                port = 1080  # Default ShinySocks port
                if len(parts) >= 2:
                    try:
                        port = int(parts[1])
                    except Exception as e:
                        raise Exception("Invalid port number given: {}. Must be int.".format(parts[1]))
                self.add_arg("port", port, ParameterType.Number)


class ShinySocksCommand(CommandBase):
    """ShinySocks command implementation for Mythic C2 - enhanced version of SOCKS"""
    
    cmd = "shinysocks"
    needs_admin = False
    help_cmd = "shinysocks [action] [port number]"
    description = "Enhanced SOCKS 4/5 compliant proxy with improved performance and features inspired by ShinySocks. Supports both SOCKS4/4a and SOCKS5 protocols with hostname resolution and advanced statistics."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@enhanced"
    argument_class = ShinySocksArguments
    attackmapping = ["T1090", "T1090.001", "T1090.002"]
    attributes = CommandAttributes(
        supported_python_versions=["Python 3.8", "Python 3.9", "Python 3.10", "Python 3.11"],
        supported_os=[SupportedOS.MacOS, SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        """Create the ShinySocks task - same structure as original SOCKS"""
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port") or 1080
        
        if action == "start":
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
                response.DisplayParams = "Started ShinySocks server on port {} with enhanced features".format(port)
                
        elif action == "stop":
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
                response.DisplayParams = "Stopped ShinySocks server"
                
        elif action == "status":
            response.DisplayParams = "Checking ShinySocks server status"
            
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """Process response from the ShinySocks task - same structure as original SOCKS"""
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp



