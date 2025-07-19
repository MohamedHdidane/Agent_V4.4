from mythic_container.MythicCommandBase import *
import subprocess
import json

class NucleiArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="ip",
                type=ParameterType.String,
                description="Internal IP or hostname of Windows target"
            )
        ]

    async def parse_arguments(self):
        if self.command_line.startswith("{"):
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("ip", self.command_line)

class NucleiCommand(CommandBase):
    cmd = "nuclei"
    needs_admin = False
    help_cmd = "nuclei 192.168.1.10"
    description = "Run a nuclei scan (from Mythic server) against the given Windows host IP"
    version = 1
    author = "@your_alias"
    argument_class = NucleiArguments

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams=taskData.args.get_arg("ip")
        )

    async def run(self, task: MythicTask) -> MythicRPCResponse:
        target_ip = task.args.get_arg("ip")

        try:
            result = subprocess.run(
                ["nuclei", "-target", target_ip, "-silent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=90,
                text=True
            )
            output = result.stdout or result.stderr or "No output"
        except Exception as e:
            output = f"[!] Failed to run nuclei: {str(e)}"

        return MythicRPCResponse(
            task_id=task.id,
            success=True,
            user_output=output
        )
