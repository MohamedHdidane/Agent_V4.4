# 📁 `watch_dir` Command – Monitor Directory for Changes

The `watch_dir` command monitors a specified directory for changes such as **file creation, deletion, updates, or moves**. It works by periodically scanning the directory and comparing state over time.

---

## 🧾 Arguments

| Argument  | Type    | Description                                                  | Required |
|-----------|---------|--------------------------------------------------------------|----------|
| `path`    | string  | Full or relative path of the directory to monitor            | ✅ Yes   |
| `seconds` | number  | Interval (in seconds) to wait between checks (default: `60`) | ❌ No    |

---

## 💻 Usage Examples

```bash
watch_dir /tmp/
watch_dir C:\Users\Public\Downloads 30
watch_dir ./workspace 15
```

- Paths can be relative or absolute.
- The optional `seconds` parameter controls how often changes are checked.
- Defaults to 60 seconds if not specified.

---

## 🔁 Behavior

- Walks the entire directory tree recursively.
- Tracks:
  - 🆕 New files/directories
  - 📝 Modified files (based on MD5 hash)
  - 🚚 Moved or renamed files
  - 🗑️ Deleted files/directories
  - 📋 Copied files (based on matching hash)
- Uses `hashlib.md5()` to fingerprint file contents.
- Sends live updates to Mythic when changes are detected.
- Stops monitoring cleanly if:
  - The job is manually stopped.
  - The root directory is deleted.

> ⚠️ Repeated I/O every polling interval – use reasonable timing to avoid CPU spikes.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                     |
|--------------|--------------------------|
| T1083        | File and Directory Discovery |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  


---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Requires **read access** to the directory and its contents.

---


