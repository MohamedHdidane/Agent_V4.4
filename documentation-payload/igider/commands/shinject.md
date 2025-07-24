# 📖 `shinject` Command – Inject Shellcode into Remote Process

The `shinject` command injects raw shellcode from an uploaded file into a **remote process** identified by its PID. It is commonly used for **in-memory execution** of payloads in post-exploitation scenarios on Windows systems.

---

## 🧾 Arguments

| Argument      | Type   | Description                               | Required |
|---------------|--------|-------------------------------------------|----------|
| `shellcode`   | `file` | Shellcode file to be uploaded and injected | ✅ Yes   |
| `process_id`  | `int`  | Target process ID to inject into           | ✅ Yes   |

---

## 💻 Usage Examples

```bash
shinject {"shellcode": "f123456", "process_id": 4120}
```

- You must upload the shellcode file first.
- The file ID (e.g., `f123456`) is used to reference the uploaded shellcode.
- Ideal for in-memory execution without touching disk post-upload.

---

## 🔁 Behavior

- Retrieves the shellcode file using its `file_id` via RPC.
- Automatically deletes the shellcode file after fetching it into memory.
- Downloads the shellcode in **base64-encoded chunks** and decodes it.
- Uses Windows APIs via `ctypes` to:
  - Open the remote process
  - Allocate executable memory (`VirtualAllocEx`)
  - Write the shellcode (`WriteProcessMemory`)
  - Execute it via `CreateRemoteThread`

> ⚠️ **Only works on Windows** and requires a valid `PID`. Behavior mimics standard process injection techniques.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                      |
|--------------|---------------------------|
| T1055        | Process Injection         |

---

## ✅ Supported Platforms

- ✅ Windows Only


---

## 🔐 Permissions

- Does **not** require administrative privileges by default.
- However, **injection into protected processes** will fail without appropriate rights.
- Requires **handle access** to the target process.

---


