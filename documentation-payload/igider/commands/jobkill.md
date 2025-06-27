# 📖 `jobkill` Command – Stop Long-Running Job

The `jobkill` command sends a stop signal to a **long-running task** on the agent. It is useful for halting stuck or unwanted background jobs without restarting the entire agent process.

---

## 🧾 Arguments

| Argument         | Type     | Description                       | Required |
|------------------|----------|-----------------------------------|----------|
| `target_task_id` | `string` | The task ID of the job to stop    | ✅ Yes   |

---

## 💻 Usage Examples

```bash
jobkill 12345
jobkill {"target_task_id": "67890"}
```

- Accepts task ID as a plain string or JSON argument.
- Only affects jobs managed by the agent that support stopping.

---

## 🔁 Behavior

- Searches the agent's internal task list for a match with `target_task_id`.
- Sets the job's internal `stopped` flag to `True`.
- Does **not** forcefully kill the process — target job must check this flag.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                          |
|--------------|-------------------------------|
| T1562.001    | Impair Defenses: Disable Tools (Optional contextual mapping if job is AV/BG task) |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  


---

## 🔐 Permissions

- Does **not** require administrative privileges.
- Can only affect jobs initiated and tracked by the current agent.

---

## ⚠️ Notes

- If the target job does not handle the `stopped` flag or ignore signals, it may not terminate.
- This command **does not** terminate system processes or OS-level threads — it's an agent-level control.

---


