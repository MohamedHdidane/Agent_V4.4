# 📖 `list_modules` Command – In-Memory Module Inspector

The `list_modules` command lists all Python modules currently **loaded in memory** on the agent. Optionally, it can show the **full internal file structure** of a specified module (e.g., a ZIP archive).

---

## 🧾 Arguments

| Argument       | Type     | Description                                             | Required |
|----------------|----------|---------------------------------------------------------|----------|
| `module_name`  | `string` | Name of the loaded module to inspect its file contents | ❌ No     |

---

## 💻 Usage Examples

```bash
list_modules
list_modules my_module.zip
```

- Without arguments, lists all in-memory modules currently loaded.
- With a module name, returns the internal file list (if the module is found).

---

## 🔁 Behavior

- Checks the `moduleRepo` dictionary in the agent.
- If `module_name` is provided:
  - Returns the file list inside that module (e.g., contents of a `.zip` or similar archive).
- If not provided:
  - Lists all currently loaded modules by name.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                        |
|--------------|-----------------------------|
| T1127        | Trusted Developer Utilities |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  



---

## 🔐 Permissions

- Does **not** require administrative privileges.
- The module must already be **loaded into memory** via other commands or operations.

---



