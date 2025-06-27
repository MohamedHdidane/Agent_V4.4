# 📖 `cat` Command – File Content Reader

The `cat` command reads and returns the **contents of a file** from the remote system. It is commonly used during post-exploitation for data gathering, configuration review, and credential harvesting.

---

## 🧾 Arguments

| Argument | Type     | Description                        | Required |
|----------|----------|------------------------------------|----------|
| `path`   | `string` | Absolute or relative path to file  | ✅ Yes   |

---

## 💻 Usage Examples

```bash
cat /etc/passwd
cat ../notes.txt
cat ./secrets.txt
```

- Relative paths are resolved from the current working directory of the agent.
- Binary or large files may not be handled well — intended for **text-based files**.

---

## 🔁 Behavior

- Uses Python's built-in `open()` in read mode.
- Joins all lines into a single string and returns the output.
- Path resolution is handled automatically:
  - If `path` is relative, it’s joined with the agent's current directory.
  - If `path` is absolute, it’s used directly.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                           |
|--------------|--------------------------------|
| T1005        | Data from Local System         |

---

## ✅ Supported Platforms

- ✅ Linux
- ✅ Windows
- ✅ macOS

Compatible with:
- Python 2.7
- Python 3.8+

---

## 🔐 Permissions

- Does **not** require administrative privileges.
- Agent must have **read permissions** on the specified file.

---

