# 📖 `unload_module` Command – Unload In-Memory Python Module

The `unload_module` command removes a previously loaded **in-memory Python module** from the agent's runtime. This is useful for **freeing memory**, **removing unused functionality**, or **resetting module state** during long-lived operations.

---

## 🧾 Arguments

| Argument      | Type     | Description                                 | Required |
|---------------|----------|---------------------------------------------|----------|
| `module_name` | `string` | Name of the module to unload (e.g. `jwt`)   | ✅ Yes   |

---

## 💻 Usage Examples

```bash
unload_module cryptography
unload_module {"module_name": "jwt"}
```

- Accepts module name as plain argument or JSON format.
- You must have **previously loaded** the module via a dynamic loader.

---

## 🔁 Behavior

- Checks if `module_name` exists in the agent’s internal `_meta_cache`.
- If found:
  - Removes its **import hook** (`sys.meta_path`).
  - Deletes the module reference from `moduleRepo`.
  - Returns success message.
- If not found:
  - Returns message indicating the module is not loaded.

> 🧠 This command only unloads modules tracked in agent memory — not system-wide Python modules.

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  

---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Only modules loaded **dynamically** by the agent can be unloaded.

---

