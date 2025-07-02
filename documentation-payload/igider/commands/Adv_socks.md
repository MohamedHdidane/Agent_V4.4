# 📖 `adv_socks` Command – Enhanced SOCKS5 Proxy Handler

The `adv_socks` command sets up or shuts down an **advanced, multithreaded SOCKS5 proxy**. It allows relaying network traffic through the agent, supporting connection pooling, batching, IPv4/IPv6/domain resolution, and detailed connection statistics.

---

## 🧾 Arguments

| Argument | Type     | Description                     | Required |
|----------|----------|---------------------------------|----------|
| `action` | `string` | `"start"` or `"stop"`           | ✅ Yes   |
| `port`   | `int`    | Port to bind the SOCKS proxy on | ✅ Yes   |

---

## 💻 Usage Examples

```bash
adv_socks start 1080
adv_socks stop 1080
```

- Starting launches the proxy on the specified port.
- Stopping terminates the running SOCKS proxy and cleans up resources.

---

## 🔁 Behavior

- Multi-threaded proxy using `select`, `queue`, and `threading`.
- Supports:
  - IPv4, IPv6, and domain-name connections
  - Real-time statistics (active/total connections, bytes transferred)
  - Efficient connection reuse (connection pool)
  - Asynchronous request handling via `a2m` and `m2a` data loops
- Includes:
  - Buffering and batching (for performance)
  - Logging and error reporting
  - Graceful shutdown of sockets and threads

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                         |
|--------------|------------------------------|
| T1572        | Protocol Tunneling           |
| T1090.001    | Proxy: Internal Proxy        |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  

Compatible with:  
- Python 3.x (recommended for full feature support)

---

## 🔐 Permissions

- Requires appropriate **network permissions** to bind sockets and communicate.
- May require elevated privileges to bind to low-numbered ports (e.g., <1024).

---

