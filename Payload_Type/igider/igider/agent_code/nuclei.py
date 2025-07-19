# agent_code/nuclei.py
def nuclei(self, task_id, ip):
    data = {
        "action": "post_response",
        "responses": [{
            "task_id": task_id,
            "user_output": f"Sent IP {ip} to Mythic for nuclei scan",
            "completed": True
        }]
    }
    self.postMessageAndRetrieveResponse(data)
    return f"Nuclei scan initiated from Mythic server for target: {ip}"
