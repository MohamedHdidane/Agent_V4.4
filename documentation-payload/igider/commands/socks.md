# 📖 `socks` Command – Start/Stop SOCKS5 Proxy Server

The `socks` command enables or disables a **SOCKS5-compliant proxy server** on the agent. This allows remote systems to route their traffic through the compromised host, facilitating pivoting inside internal networks.

---

## 🧾 Arguments

| Argument | Type     | Description                                            | Required |
|----------|----------|--------------------------------------------------------|----------|
| `action` | `string` | Either `"start"` or `"stop"` to control the proxy      | ✅ Yes   |
| `port`   | `number` | Port on which to start the SOCKS5 proxy (default: 7005) | ❌ No    |

---

## 💻 Usage Examples

```bash
socks start
socks start 7005
socks stop
socks {"action": "start", "port": 8000}
```

- `start`: Spins up a SOCKS5 proxy server on the specified port.
- `stop`: Terminates the SOCKS5 proxy session.
- If no port is provided during `start`, defaults to `7005`.

---

## 🔁 Behavior

- On `start`:
  - Sets up a background SOCKS5 proxy server.
  - Opens the specified port and starts listening for incoming SOCKS requests.
  - Supports IPv4 and domain-based addressing for target destinations.
  - Handles multiple connections using threads and queues.
- On `stop`:
  - Shuts down all active SOCKS threads associated with the current task.
  - Cleans up queues and open connections.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                                 |
|--------------|--------------------------------------|
| T1090        | Proxy                                |
| T1572        | Protocol Tunneling (optional context)|

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  


---

## 🔐 Permissions

- Does **not** require administrative privileges.
- Requires ability to bind to local port (some low ports may need elevation).
- Uses system sockets to forward data, so firewall/NAT rules may apply.

---

## ⚠️ Notes

- Max number of threads is limited (`MAX_THREADS = 200`) to prevent overload.
- Incoming connections must speak SOCKS5 — no authentication supported (`NOAUTH` only).
- Good for lateral movement in post-exploitation scenarios where pivoting is necessary.

---


