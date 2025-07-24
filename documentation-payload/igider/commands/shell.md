# 📖 `shell` Command – Execute Terminal Commands

The `shell` command runs a **system shell command** directly on the target machine. It enables interaction with the operating system using native command-line instructions and returns the output back to the operator.

---

## 🧾 Arguments

| Argument   | Type     | Description                 | Required |
|------------|----------|-----------------------------|----------|
| `command`  | `string` | The shell command to execute | ✅ Yes   |

---

## 💻 Usage Examples

```bash
shell whoami
shell ls -la /var/log
shell ipconfig /all
```

- Any OS-specific shell command is supported.
- Output includes both `stdout` and `stderr`.
- The agent will return command output to the C2.

---

## 🔁 Behavior

- Command is executed using:
  - `cmd.exe` on Windows
  - `/bin/sh` or equivalent on Linux/macOS
- Captures both `stdout` and `stderr` via `subprocess.Popen`.
- Automatically resolves current working directory from the agent context.
- Does **not** spawn a persistent shell — each invocation is single-run.

> ⚠️ **Be careful**: Shell commands can alter the system or reveal agent presence if misused.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                          |
|--------------|-------------------------------|
| T1059        | Command and Scripting Interpreter |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS   

---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Execution is limited by the current user's OS-level permissions.

---



