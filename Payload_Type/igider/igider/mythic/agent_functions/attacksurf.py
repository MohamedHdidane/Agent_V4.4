# mythic/agent_functions/attacksurf.py
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json

class AttackSurfaceArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(name="cidrs", type=ParameterType.String, description="Comma-separated CIDR(s) to scan"),
            CommandParameter(name="top_ports", type=ParameterType.Number, description="Number of top TCP ports"),
            CommandParameter(name="banners", type=ParameterType.Boolean, description="Grab simple TCP banners"),
            CommandParameter(name="http", type=ParameterType.Boolean, description="HTTP title/server fingerprint"),
            CommandParameter(name="timeout_ms", type=ParameterType.Number, description="Per-connection timeout ms"),
            CommandParameter(name="rate", type=ParameterType.Number, description="Max concurrent probes"),
            CommandParameter(name="max_hosts", type=ParameterType.Number, description="Limit hosts fully scanned")
        ]

    async def parse_arguments(self):
        # Accept raw JSON or simple string (CIDR)
        if len(self.command_line) == 0:
            # No args: everything default
            return
        if self.command_line.strip().startswith("{"):
            temp = json.loads(self.command_line)
            for k,v in temp.items():
                if k in self.get_parameter_names():
                    self.set_arg(k, v)
        else:
            # Assume single CIDR argument (optionally quoted)
            cmd = self.command_line.strip()
            if (cmd[0] == '"' and cmd[-1] == '"') or (cmd[0]=="'" and cmd[-1]=="'"):
                cmd = cmd[1:-1]
            self.set_arg("cidrs", cmd)

class AttackSurfaceCommand(CommandBase):
    cmd = "attacksurf"
    needs_admin = False
    help_cmd = "attacksurf [cidr|json options]"
    description = "Map reachable network attack surface (hosts, ports, banners) quickly."
    version = 1
    author = "@you"
    attackmapping = ["T1046","T1018","T1049"]  # Network Service Discovery, Remote System Discovery, System Network Connections Discovery
    argument_class = AttackSurfaceArguments
    attributes = CommandAttributes(
        supported_os=[ SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS ]
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        cidrs = taskData.args.get_arg("cidrs") if taskData.args.has_arg("cidrs") else "(auto)"
        top_ports = taskData.args.get_arg("top_ports") if taskData.args.has_arg("top_ports") else 20
        resp.DisplayParams = f"{cidrs} top_ports={top_ports}"
        return resp

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        """
        Expect incremental 'chunk' messages:
        {
          "chunk": 3,
          "total_chunks": 10,
          "hosts": [ {...}, {...} ]
        }
        Final message may include summary stats.
        """
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
