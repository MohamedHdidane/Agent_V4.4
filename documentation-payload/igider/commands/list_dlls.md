# 📖 `list_dlls` Command – List DLLs Loaded in a Process

The `list_dlls` command retrieves a list of **loaded DLLs** from a specific process or from the current process if no PID is provided. This is useful for identifying injected or suspicious modules during post-exploitation.

---

## 🧾 Arguments

| Argument     | Type     | Description                                                                 | Required |
|--------------|----------|-----------------------------------------------------------------------------|----------|
| `process_id` | `number` | ID of the target process. Use `0` or omit to list DLLs of the current agent | ❌ No    |

---

## 💻 Usage Examples

```bash
list_dlls
list_dlls 1234
list_dlls {"process_id": 4321}
```

- `list_dlls`: Lists loaded DLLs for the current running agent process.
- `list_dlls 1234`: Lists DLLs in the process with PID 1234.
- JSON form (`{"process_id": 4321}`) is supported for structured input.

---

## 🔁 Behavior

- Uses Windows API and native memory reading techniques to safely enumerate loaded modules.
- Traverses the PEB (Process Environment Block) to walk the in-memory module list.
- DLL paths are returned in full UNC or drive-letter format.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                          |
|--------------|-------------------------------|
| T1055.001    | Process Injection: DLL Injection |
| T1012        | Query Registry (by implication) |
| T1057        | Process Discovery             |

---

## ✅ Supported Platforms

- ✅ Windows only  
- 🧪 Compatible with:
  - Python 3.8 (required)
  - Windows 10, 11, Server

---

## 🔐 Permissions

- Does **not** require administrative rights if the target process is accessible.
- May fail for system processes or protected processes due to permission restrictions.
- Uses `ReadProcessMemory` and `NtQueryInformationProcess`, so access errors may occur.

---

## ⚠️ Notes

- Output is a JSON structure with a `dlls` array of full DLL paths.
- If the command fails, an exception message will be returned instead.
- Uses a custom remote pointer type system to dereference PEB structures reliably.

---




