# 📖 `ps` Command – Cross-Platform Process Lister (Limited)

The `ps` command retrieves a **lightweight list of running processes** on the target system, including basic metadata like names, PIDs, and binary paths. It supports both Windows and Linux, making it ideal for initial reconnaissance.

---

## 🧾 Arguments

| Argument | Type | Description             | Required |
|----------|------|-------------------------|----------|
| _None_   | —    | No arguments are needed | ❌ No    |

---

## 💻 Usage Examples

```bash
ps
```

- Displays a basic list of processes with available metadata.
- Useful when deep introspection (`ps_full`) is not required or supported.

---

## 🔁 Behavior

- **Linux**:
  - Parses `/proc/[pid]/status` and `/proc/[pid]/cmdline`.
  - Maps UID to usernames using `/etc/passwd`.
  - Returns:
    - `process_id`
    - `parent_process_id`
    - `user_id`
    - `name`
    - `bin_path`

- **Windows**:
  - Uses `EnumProcesses`, `OpenProcess`, and `GetProcessImageFileNameA`.
  - Resolves internal device paths to Win32 paths using `QueryDosDeviceW`.
  - Returns:
    - `process_id`
    - `architecture` (`x86` or `x64`)
    - `name`
    - `bin_path`

> 🧠 A simpler and faster alternative to `ps_full`, intended for surface-level inspection.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name        |
|--------------|-------------|
| T1106        | Native API  |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
 

---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Access to some processes may be restricted depending on OS-level permissions.

---

