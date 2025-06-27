# 📖 `jobs` Command – List Running Jobs

The `jobs` command lists all **active or background jobs** currently managed by the agent. It is useful for monitoring long-running or asynchronous tasks and identifying task IDs that can be stopped or inspected further.

---

## 🧾 Arguments

| Argument | Type | Description             | Required |
|----------|------|-------------------------|----------|
| _None_   | —    | This command takes none | ❌ No    |

---

## 💻 Usage Examples

```bash
jobs
```

- Displays all currently tracked jobs by the agent.
- Useful before using `jobkill` to reference valid task IDs.

---

## 🔁 Behavior

- Returns a list of tasks that are marked as background or long-running.
- The output format depends on the agent implementation but typically includes:
  - Task ID
  - Command name
  - Status (`running`, `stopped`, etc.)
  - Start time or duration
- Output is typically shown in a table or JSON in the Mythic UI.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                  |
|--------------|-----------------------|
| T1057        | Process Discovery (if job is a task representation of a process) |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  


---

## 🔐 Permissions

- Does **not** require administrative privileges.
- Only reflects jobs created and tracked by the agent.

---


