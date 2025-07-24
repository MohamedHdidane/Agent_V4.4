# 📖 `load` Command – Dynamically Load Agent Commands

The `load` command dynamically loads a **previously unused command** into the agent by retrieving its code from the Mythic server. This enables live extension of the agent's capabilities during an operation, without requiring a new payload.

---

## 🧾 Arguments

| Argument  | Type       | Description                                 | Required |
|-----------|------------|---------------------------------------------|----------|
| `command` | `chooseOne`| Name of the command to load (auto-populated)| ✅ Yes   |

---

## 💻 Usage Examples

```bash
load
```

> Select a command from the dropdown in the UI, or supply a command name via JSON:

```json
{
  "command": "load_module"
}
```

- Lists all commands **available for the agent but not yet loaded**.
- Once selected, the command is loaded in-memory and registered for use.

---

## 🔁 Behavior

- Queries Mythic to determine supported commands for the current agent config (OS + Python version).
- Filters out already-loaded commands to avoid duplication.
- Loads the source code from the Mythic agent repo (`.py`, `.py2`, or `.py3`).
- Sends the command code to the agent, executes it via `exec()`, and attaches it to the agent class.
- Registers the new command with the C2 interface for immediate use.

> ⚙️ Uses `setattr()` to register the command dynamically and adds it to the agent's internal dispatcher.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                                  |
|--------------|---------------------------------------|
| T1030        | Data Transfer Tool                    |
| T1129        | Shared Modules                        |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  



---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Agent must have **sufficient resources** to execute new code and store it in memory.

---

