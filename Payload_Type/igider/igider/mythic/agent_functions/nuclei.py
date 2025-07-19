from mythic_container.MythicCommandBase import *
import subprocess
import json
import re
import ipaddress

class NucleiArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="target",
                type=ParameterType.String,
                description="Target IP, hostname, or CIDR range",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="templates",
                type=ParameterType.String,
                description="Comma-separated template tags (e.g., cve,rce,sqli)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="severity",
                type=ParameterType.String,
                description="Minimum severity: info,low,medium,high,critical",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="timeout",
                type=ParameterType.Number,
                description="Scan timeout in seconds (default: 300)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Require a target to scan.\n\tUsage: {}".format(NucleiCommand.help_cmd))
        
        if self.command_line[0] == "{":
            # JSON format
            temp_json = json.loads(self.command_line)
            self.args[0].value = temp_json.get("target", "")
            self.args[1].value = temp_json.get("templates", "")
            self.args[2].value = temp_json.get("severity", "")
            self.args[3].value = temp_json.get("timeout", 300)
        else:
            # Simple target format
            target = self.command_line.strip()
            if target[0] == '"' and target[-1] == '"':
                target = target[1:-1]
            elif target[0] == "'" and target[-1] == "'":
                target = target[1:-1]
            self.args[0].value = target
            self.args[1].value = ""
            self.args[2].value = ""
            self.args[3].value = 300

class NucleiCommand(CommandBase):
    cmd = "nuclei"
    needs_admin = False
    help_cmd = 'nuclei 192.168.1.10 or nuclei {"target": "192.168.1.0/24", "templates": "cve,rce", "severity": "high"}'
    description = "Run a nuclei vulnerability scan (from Mythic server) against the given target"
    version = 1
    author = "@your_alias"
    supported_ui_features = []
    parameters = []
    attackmapping = ["T1046", "T1595.002"]
    argument_class = NucleiArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        target = taskData.args.get_arg("target")
        templates = taskData.args.get_arg("templates")
        severity = taskData.args.get_arg("severity")
        
        display_params = f"Target: {target}"
        if templates:
            display_params += f", Templates: {templates}"
        if severity:
            display_params += f", Severity: {severity}"
            
        response.DisplayParams = display_params
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp