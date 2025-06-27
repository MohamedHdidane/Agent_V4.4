# 📂 `ls` Command – File & Directory Enumeration

The `ls` command allows you to **list and inspect files or directories** on the target system, returning rich metadata including file size, permissions, timestamps, and more.

This command is fundamental in post-exploitation tasks such as file reconnaissance, persistence detection, or lateral movement planning — especially in agent-based red team operations.

---

## 🧾 Arguments

| Argument   | Type   | Description                                        | Required | Default |
|------------|--------|----------------------------------------------------|----------|---------|
| `path`     | `str`  | Target file or directory path                      | ✅ Yes   | `.`     |

- Supports both **absolute** and **relative** paths.
- If `.` is passed, it uses the agent’s current working directory.

---

## 💻 Usage Examples

```bash
ls /etc              # List contents of /etc
ls .                 # Enumerate current directory
ls ../Downloads      # Relative path to parent Downloads directory
```

---

## 🧠 What It Returns

The output is a structured JSON object containing metadata:

- 📁 **Name** and **type** (file or directory)
- 🔒 **Permissions** (octal format)
- 🕒 **Access** and **modification times** (UNIX timestamp in ms)
- 📦 **File size**
- 📂 **Parent path** for context


---

## ⚙️ Behavior Notes

- Respects symbolic links and filesystem boundaries (no recursion).
- Automatically handles `PermissionError` and missing files gracefully.
- Timestamps are in **milliseconds** (UTC-based).
- Designed for **integration with UI-based file browsers** in agent systems.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                          |
|--------------|-------------------------------|
| T1083        | File and Directory Discovery  |
| T1106        | Native Command Execution      |

---

## ✅ Tested Platforms

- ✅ Linux (Debian, Ubuntu, Kali)
- ✅ Windows (10, 11, Server)
- ✅ macOS (limited)

---


