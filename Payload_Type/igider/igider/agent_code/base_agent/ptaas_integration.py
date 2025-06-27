import json
import requests
from datetime import datetime
from typing import Dict, Any, Optional

class PTaaSIntegration:
    """
    PTaaS (Pentest as a Service) integration module for the Mythic agent.
    Handles communication with the PTaaS platform for automated testing workflows.
    """
    
    def __init__(self, agent_core):
        self.agent_core = agent_core
        self.ptaas_config = {
            "api_url": "PTAAS_API_URL_PLACEHOLDER",
            "api_key": "PTAAS_API_KEY_PLACEHOLDER",
            "engagement_id": "PTAAS_ENGAGEMENT_ID_PLACEHOLDER",
            "enabled": "PTAAS_ENABLED_PLACEHOLDER"
        }
        
    def is_enabled(self) -> bool:
        """Check if PTaaS integration is enabled."""
        return self.ptaas_config.get("enabled", "false").lower() == "true"
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to PTaaS platform."""
        if not self.is_enabled():
            return False
            
        try:
            data = {
                "agent_id": self.agent_core.agent_config.get("UUID", ""),
                "timestamp": datetime.now().isoformat(),
                "status": "active",
                "engagement_id": self.ptaas_config["engagement_id"],
                "host_info": {
                    "hostname": self.agent_core.agent_config.get("hostname", ""),
                    "ip": self.agent_core.agent_config.get("ip", ""),
                    "os": self.agent_core.getOSVersion(),
                    "user": self.agent_core.getUsername()
                }
            }
            
            headers = {
                "Authorization": f"Bearer {self.ptaas_config['api_key']}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                f"{self.ptaas_config['api_url']}/api/v1/agents/heartbeat",
                json=data,
                headers=headers,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            # Log error but don't fail the agent
            return False
    
    def report_task_result(self, task_id: str, command: str, result: str, success: bool) -> bool:
        """Report task execution result to PTaaS platform."""
        if not self.is_enabled():
            return False
            
        try:
            data = {
                "agent_id": self.agent_core.agent_config.get("UUID", ""),
                "task_id": task_id,
                "command": command,
                "result": result,
                "success": success,
                "timestamp": datetime.now().isoformat(),
                "engagement_id": self.ptaas_config["engagement_id"]
            }
            
            headers = {
                "Authorization": f"Bearer {self.ptaas_config['api_key']}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                f"{self.ptaas_config['api_url']}/api/v1/tasks/results",
                json=data,
                headers=headers,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception as e:
            return False
    
    def get_automated_tasks(self) -> list:
        """Retrieve automated tasks from PTaaS platform."""
        if not self.is_enabled():
            return []
            
        try:
            headers = {
                "Authorization": f"Bearer {self.ptaas_config['api_key']}",
                "Content-Type": "application/json"
            }
            
            params = {
                "agent_id": self.agent_core.agent_config.get("UUID", ""),
                "engagement_id": self.ptaas_config["engagement_id"]
            }
            
            response = requests.get(
                f"{self.ptaas_config['api_url']}/api/v1/tasks/automated",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json().get("tasks", [])
            else:
                return []
                
        except Exception as e:
            return []
    
    def upload_evidence(self, evidence_type: str, data: bytes, filename: str) -> bool:
        """Upload evidence (files, screenshots, etc.) to PTaaS platform."""
        if not self.is_enabled():
            return False
            
        try:
            headers = {
                "Authorization": f"Bearer {self.ptaas_config['api_key']}"
            }
            
            files = {
                "file": (filename, data, "application/octet-stream")
            }
            
            data_payload = {
                "agent_id": self.agent_core.agent_config.get("UUID", ""),
                "engagement_id": self.ptaas_config["engagement_id"],
                "evidence_type": evidence_type,
                "timestamp": datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{self.ptaas_config['api_url']}/api/v1/evidence/upload",
                headers=headers,
                files=files,
                data=data_payload,
                timeout=30
            )
            
            return response.status_code == 200
            
        except Exception as e:
            return False

def ptaas_enhanced_checkin(self):
    """Enhanced check-in that includes PTaaS integration."""
    # Perform standard check-in first
    standard_checkin_result = self.checkIn()
    
    if standard_checkin_result and hasattr(self, 'ptaas'):
        # Send heartbeat to PTaaS platform
        self.ptaas.send_heartbeat()
    
    return standard_checkin_result

def ptaas_enhanced_process_task(self, task):
    """Enhanced task processing with PTaaS reporting."""
    # Store original processTask method
    original_result = self.processTask(task)
    
    # Report to PTaaS if enabled
    if hasattr(self, 'ptaas') and self.ptaas.is_enabled():
        self.ptaas.report_task_result(
            task.get("task_id", ""),
            task.get("command", ""),
            task.get("result", ""),
            not task.get("error", False)
        )
    
    return original_result

def ptaas_get_automated_tasks(self):
    """Get automated tasks from PTaaS platform and add them to the task queue."""
    if hasattr(self, 'ptaas') and self.ptaas.is_enabled():
        automated_tasks = self.ptaas.get_automated_tasks()
        
        for ptaas_task in automated_tasks:
            # Convert PTaaS task format to Mythic task format
            mythic_task = {
                "task_id": ptaas_task.get("id", ""),
                "command": ptaas_task.get("command", ""),
                "parameters": json.dumps(ptaas_task.get("parameters", {})),
                "result": "",
                "completed": False,
                "started": False,
                "error": False,
                "stopped": False,
                "ptaas_task": True  # Mark as PTaaS-originated task
            }
            
            self.taskings.append(mythic_task)

