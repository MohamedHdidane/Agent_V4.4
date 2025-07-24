# 📤 `upload` Command – Upload Files to Target

The `upload` command transfers a **file from the operator's machine to the target system**. It supports full paths or directory destinations and is compatible with Mythic’s file browser UI.

---

## 🧾 Arguments

| Argument      | Type   | Description                                    | Required |
|---------------|--------|------------------------------------------------|----------|
| `file`        | `file` | The file to upload, selected via Mythic UI     | ✅ Yes   |
| `remote_path` | string | Destination path on the target system          | ✅ Yes   |

---

## 💻 Usage Examples

```bash
upload file=payload.bin remote_path=/tmp/
upload file=keylogger.exe remote_path=C:\Users\Public\
upload file=script.sh remote_path=./tools/
```

- If `remote_path` ends with a slash (`/` or `\`), the original filename is appended automatically.
- Relative paths are resolved against the agent’s current working directory.

---

## 🔁 Behavior

- Retrieves metadata for the uploaded file using `SendMythicRPCFileSearch()`.
- If `remote_path` is not provided, defaults to the original file name.
- Resolves full destination path and displays parameters like:
  - `"payload.bin to /tmp/payload.bin"`
- Handles chunked file upload with:
  - `chunk_num`
  - `total_chunks`
  - `chunk_data` (base64-encoded)
- Uses the agent’s `postMessageAndRetrieveResponse()` to request and write file chunks sequentially.

> ⚠️ File is written using `open(..., "wb")` — ensure the target path is valid and writable.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                       |
|--------------|----------------------------|
| T1105        | Ingress Tool Transfer      |
| T1132        | Data Encoding              |
| T1030        | Data Transfer Size Limits  |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  

---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Requires sufficient **write** access to the specified `remote_path`.

---


