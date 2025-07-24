# 📖 `load_script` Command – In-Memory Python Script Loader

The `load_script` command uploads and executes a **Python script directly into memory**. Its functions and logic become available at runtime and can be used dynamically via `eval_code()` or by attaching functions to the agent using `setattr()`.

---

## 🧾 Arguments

| Argument | Type   | Description           | Required |
|----------|--------|-----------------------|----------|
| `file`   | `file` | Python script to load | ✅ Yes   |

---

## 💻 Usage Examples

```bash
load_script
```

> Requires input via JSON or UI:
```json
{
  "file": "def456"
}
```

- Uploads a `.py` script from Mythic and executes it in the agent context.
- Functions defined inside the script can later be called dynamically.

---

## 🔁 Behavior

- Retrieves the file in chunks from Mythic.
- Decodes and joins the script content.
- Executes the script using Python’s built-in `exec()`.
- Script logic is **not persisted on disk** and is executed in-memory only.

> You can extend the agent’s functionality temporarily or inject helper functions dynamically.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                                  |
|--------------|---------------------------------------|
| T1059.006    | Command and Scripting Interpreter: Python |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  



---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Python syntax in the script must be compatible with the agent's interpreter.

---

