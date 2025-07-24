# 📖 `load_dll` Command – Load and Execute DLL Export

The `load_dll` command loads a **DLL file from disk** and **executes a specified export** function using `ctypes.WinDLL`. It is useful for running in-memory tooling or invoking custom logic delivered through DLLs.

---

## 🧾 Arguments

| Argument     | Type     | Description                                | Required |
|--------------|----------|--------------------------------------------|----------|
| `dllpath`    | `string` | Path to the DLL file on disk               | ✅ Yes   |
| `dllexport`  | `string` | Name of the export function to execute     | ✅ Yes   |

---

## 💻 Usage Examples

```bash
load_dll C:\Tools\payload.dll run
load_dll ./bin/stealth.dll init
```

- The command accepts either absolute or relative paths.
- The specified export function is called immediately after the DLL is loaded.

---

## 🔁 Behavior

- Uses Python's `ctypes.WinDLL()` to load the specified DLL.
- Calls the provided export function via `eval("loaded_dll.<export>()")`.
- Resolves relative paths from the agent's current working directory.

⚠️ **Note:** If the export function performs malicious or long-running operations, ensure the task lifecycle is managed properly.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                                  |
|--------------|---------------------------------------|
| T1059.006    | Command and Scripting Interpreter: Python |
| T1127        | Trusted Developer Utilities: DLL       |

---

## ✅ Supported Platforms

- ✅ Windows  


---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- The DLL file must be **accessible on disk** and contain the specified export.

---




