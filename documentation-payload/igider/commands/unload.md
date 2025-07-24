# 📤 `upload` Command – Upload Files to Target

The `upload` command allows the operator to **transfer a file** from their local machine to the target system. It can be used via the file browser interface or by specifying a destination path directly.

---

## 🧾 Arguments

| Argument      | Type   | Description                              | Required |
|---------------|--------|------------------------------------------|----------|
| `file`        | `file` | The file to upload (select from UI)      | ✅ Yes   |
| `remote_path` | string | Destination path on the remote machine   | ✅ Yes   |

---

## 💻 Usage Examples

```bash
upload file=beacon.exe remote_path=/tmp/
upload file=report.pdf remote_path=C:\Users\Public\Documents\
```

- Uploads can be triggered manually or via the file browser.
- If `remote_path` ends in `/`, the file retains its original name.
- If `remote_path` is a full file path, the uploaded file will be renamed accordingly.

---

## 🔁 Behavior

- Uses `SendMythicRPCFileSearch` to fetch the file metadata.
- Automatically resolves the final destination path based on the original filename if `remote_path` is a directory.
- Operates across all supported platforms with proper file handling.
- Displays parameters like:
  - `"beacon.exe to /tmp/beacon.exe"`

> ⚠️ **Ensure sufficient disk space** and permissions exist on the target system.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                       |
|--------------|----------------------------|
| T1132        | Data Encoding              |
| T1030        | Data Transfer Size Limits  |
| T1105        | Ingress Tool Transfer      |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  


---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- The agent must have **write permissions** to the target location.

---

