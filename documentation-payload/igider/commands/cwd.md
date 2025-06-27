# 📍 `cwd` Command – Get Current Working Directory

The `cwd` command retrieves the **agent’s current working directory**. It’s especially useful when navigating file systems remotely or when relative paths are used with other commands like `ls`, `cd`, or `download`.

---

## 🧾 Arguments

This command takes **no arguments**.

| Argument | Type | Description             | Required |
|----------|------|-------------------------|----------|
| *(none)* | —    | No input is necessary.  | ❌ No    |

---

## 💻 Usage Example

```bash
cwd
```

Example output:

```
/home/user/documents
```

---

## 🔁 Behavior

- Returns the path to the agent's internal `current_directory` variable.
- Useful for validation after using `cd`, or when building file paths dynamically.
- Output is a clean, absolute path.

---

## 🧠 Integration Tip

Use `cwd` in scripts or GUI panels to **display path context** before interacting with the file system.

---

## ✅ Supported Platforms

- ✅ Linux
- ✅ Windows
- ✅ macOS



---

## 🔐 Permissions

- Does **not** require administrative privileges.
- Safe for all users and contexts.

---

## 🧩 MITRE ATT&CK Mapping

> No direct ATT&CK technique mapping. Utility command for agent state introspection.

---

