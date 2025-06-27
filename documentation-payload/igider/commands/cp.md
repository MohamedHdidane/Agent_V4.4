# 📄 `cp` Command – Copy Files or Directories

The `cp` command copies a **file or directory** from a source path to a destination path on the target system. It supports both absolute and relative paths and is useful for staging files, backup operations, or data preparation.

---

## 🧾 Arguments

| Argument      | Type     | Description                                  | Required |
|---------------|----------|----------------------------------------------|----------|
| `source`      | `string` | Path to the file or folder to copy           | ✅ Yes   |
| `destination` | `string` | Path to the target destination               | ✅ Yes   |

- Paths can be **absolute** or **relative** to the agent's current working directory.
- Automatically detects whether the source is a file or directory.

---

## 💻 Usage Examples

```bash
cp /tmp/config.yaml /tmp/config.bak
cp ./secrets.txt ../backup/
cp folder1 /tmp/copied_folder
```

---

## 🔁 Behavior

- Resolves paths based on current working directory unless absolute.
- If the source is a **file**, performs a `shutil.copy()`.
- If the source is a **directory**, performs a recursive `shutil.copytree()`.
- Automatically handles path normalization and validation.

> ⚠️ The destination directory must be writable by the agent process.

---

## 🔐 Permissions

- Does **not** require administrative privileges.
- The agent must have **read access** to the source and **write access** to the destination.

---

## ✅ Supported Platforms

- ✅ Linux
- ✅ Windows
- ✅ macOS


---

## 🧩 MITRE ATT&CK Mapping

> No direct ATT&CK mapping. This command supports operational setup and post-exploitation objectives.

---

