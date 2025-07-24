# 📖 `mv` Command – Move Files or Directories

The `mv` command moves a **file or directory** from one location to another on the remote system. This is useful for organizing files, evading detection, or preparing data for exfiltration.

---

## 🧾 Arguments

| Argument     | Type     | Description                                   | Required |
|--------------|----------|-----------------------------------------------|----------|
| `source`     | `string` | Path to the file or folder to move            | ✅ Yes   |
| `destination`| `string` | Target path or directory for the move         | ✅ Yes   |

---

## 💻 Usage Examples

```bash
mv /tmp/loot.txt /var/backups/loot.txt
mv myfolder /home/user/archived_data/
```

- Accepts both absolute and relative paths.
- Automatically resolves paths from the agent’s current working directory if not absolute.

---

## 🔁 Behavior

- Uses Python's `shutil.move()` to perform the operation.
- Handles files and folders alike.
- Will **overwrite** the destination if a file with the same name already exists.

> 🛠 Note: No confirmation prompt — ensure destination path is valid before running.

---

## 🧩 MITRE ATT&CK Mapping

_No direct mapping; useful as a support function during various stages of attack._

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  


---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Agent must have appropriate **read/write** permissions on both source and destination paths.

---

