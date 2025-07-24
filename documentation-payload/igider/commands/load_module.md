# 📖 `load_module` Command – In-Memory Python Library Loader

The `load_module` command uploads a **zipped Python module** (e.g., `.zip` file containing `.py` files or packages) and loads it **directly into memory** using a custom module loader. This allows runtime extension of the agent's capabilities without writing to disk.

---

## 🧾 Arguments

| Argument      | Type   | Description                                | Required |
|---------------|--------|--------------------------------------------|----------|
| `file`        | `file` | Zipped Python library to load              | ✅ Yes   |
| `module_name` | string | Name to assign to the loaded module        | ✅ Yes   |

---

## 💻 Usage Examples

```bash
load_module
```

> Requires input via JSON or UI:
```json
{
  "file": "abc123", 
  "module_name": "cryptography"
}
```

- Uploads a zip-compressed Python module and makes it available via `import` in the agent.
- The `module_name` is used as a key to reference and import the module dynamically.

---

## 🔁 Behavior

- The agent:
  - Downloads the file chunk-by-chunk from Mythic.
  - Caches the zip file in memory (`moduleRepo[module_name]`).
  - Installs a custom `CFinder` loader using `sys.meta_path` to intercept future imports.
- The module can then be imported as usual using `import <module_name>`.

⚠️ Note:
- Only zipped modules are supported.
- Does not persist on disk — in-memory only.
- Duplicate loading is prevented unless the module is removed manually.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                        |
|--------------|-----------------------------|
| T1059.006    | Command and Scripting Interpreter: Python |
| T1127        | Trusted Developer Utilities |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  

 

---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Uploaded file must be a **valid zip-compressed Python module**.

---

