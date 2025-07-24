# 📖 `rm` Command – Remove Files or Directories

The `rm` command deletes a **file or directory** from the remote system. It supports both absolute and relative paths and can be triggered from the file browser UI or directly via the command line.

---

## 🧾 Arguments

| Argument | Type     | Description                            | Required |
|----------|----------|----------------------------------------|----------|
| `path`   | `string` | Path to the file or directory to delete | ✅ Yes   |

---

## 💻 Usage Examples

```bash
rm /tmp/sensitive.txt
rm ./old_logs/
```

- Accepts both absolute and relative paths.
- Can be used via the file browser context menu or directly typed.

---

## 🔁 Behavior

- Resolves the path relative to the agent's current working directory if not absolute.
- Deletes:
  - Files using `os.remove()`
  - Directories using `shutil.rmtree()`
- Can remove folders recursively.

> ⚠️ **Destructive action** — deleted files and folders **cannot be recovered** by the agent.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name              |
|--------------|-------------------|
| T1485        | Data Destruction  |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  

---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Agent must have sufficient **write/delete** permissions for the target file or directory.

---

