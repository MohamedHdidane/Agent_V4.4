# 📖 `ps_full` Command – Detailed Process Listing (Windows)

The `ps_full` command retrieves a **comprehensive list of running processes** on a Windows system, including image paths, architectures, command-line arguments, parent processes, and integrity levels. It uses Windows APIs and memory introspection for enhanced visibility.

---

## 🧾 Arguments

| Argument | Type | Description             | Required |
|----------|------|-------------------------|----------|
| _None_   | —    | No arguments are needed | ❌ No    |

---

## 💻 Usage Examples

```bash
ps_full
```

- Returns a detailed list of all processes, including low-level fields.
- Can be used in Mythic’s process browser interface (`process_browser:list`).

---

## 🔁 Behavior

- Uses `EnumProcesses` from `Psapi.dll` to get all process IDs.
- For each process, uses:
  - `OpenProcess` for handle acquisition.
  - `NtQueryInformationProcess` for basic info and PEB parsing.
  - `ReadProcessMemory` to extract command-line, image path, and other metadata.
  - `IsWow64Process` to determine architecture.
- Fields extracted:
  - `process_id`
  - `parent_process_id`
  - `architecture` (`x86` or `x64`)
  - `image_path`
  - `command_line`
  - `integrity_level` (via session ID)

> 🧠 Deep memory parsing and Windows internal structures (PEB, UNICODE_STRING, etc.) are used to provide rich process metadata.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                    |
|--------------|-------------------------|
| T1106        | Native API              |

---

## ✅ Supported Platforms

- ✅ Windows  

---

## 🔐 Permissions

- Does **not** require administrative privileges by default.  
- Some processes may fail to open or read, depending on access rights.

---

