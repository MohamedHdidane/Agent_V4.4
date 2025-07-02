from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *

class PrivEscArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass  # No arguments required for priv_esc

class PrivEscCommand(CommandBase):
    cmd = "priv_esc"
    needs_admin = False
    help_cmd = "priv_esc"
    description = "Perform privilege escalation checks on the target system (e.g., sudo rights, writable system files)."
    version = 1
    supported_ui_features = ["privesc:check"]
    is_download_file = False
    parameters = []
    attackmapping = ["T1068", "T1548"]
    argument_class = PrivEscArguments
    browser_script = BrowserScript(script_name="priv_esc", author="@Med", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Linux, SupportedOS.Windows, SupportedOS.MacOS],
        is_platform_specific = True,
    )
    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = "Running privilege escalation checks"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp