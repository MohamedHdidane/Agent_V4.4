# 📖 `kill` Command – Terminate Process by ID

The `kill` command sends a termination signal to a specified **process ID (PID)** on the target system. It is typically used to stop rogue processes, malware, or cleanup tasks during post-exploitation.

---

## 🧾 Arguments

| Argument     | Type     | Description                      | Required |
|--------------|----------|----------------------------------|----------|
| `process_id` | `number` | The ID (PID) of the process to kill | ✅ Yes   |

---

## 💻 Usage Examples

```bash
kill 1234
kill {"process_id": 4567}
```

- Accepts PID directly or as a JSON argument.
- Only valid process IDs that the agent can access will be terminated.

---

## 🔁 Behavior

- Sends a termination request to the given process ID.
- Behavior may vary based on permissions and OS restrictions:
  - On Windows, uses standard system API calls to terminate the process.
- Displays confirmation in Mythic UI if successful.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                    |
|--------------|-------------------------|
| T1057        | Process Discovery       |
| T1106        | Native API              |
| T1561.001    | Disk Wipe: Windows     |

---

## ✅ Supported Platforms

- ✅ Windows (Only)  


---

## 🔐 Permissions

- Does **not** require administrative privileges by default.
- The agent must have permission to access and terminate the target process.
- Some processes may be protected or owned by SYSTEM and cannot be killed without elevation.

---


