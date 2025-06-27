# 📁 `cd` Command – Change Directory

The `cd` command updates the agent’s **current working directory**, allowing other file-related commands (like `ls`, `cat`, `download`) to resolve relative paths accordingly.

---

## 🧾 Arguments

| Argument | Type     | Description                                          | Required | Default |
|----------|----------|------------------------------------------------------|----------|---------|
| `path`   | `string` | Target directory path (absolute or relative)        | ❌ No    | `.`     |

- `".."` moves one level up in the directory structure.
- `"."` keeps the agent in the current directory.
- Relative paths are resolved based on the current working directory.

---

## 💻 Usage Examples

```bash
cd /var/log
cd ..
cd ../Documents
cd C:\\Users\\Public
```

---

## 🔁 Behavior

- If `path == ".."`:
  - The agent moves one directory up (similar to `cd ..` in shell).
- If the path is **absolute**, it sets it directly.
- If the path is **relative**, it joins it with the current directory and normalizes it using `os.path.abspath()`.

> The agent’s internal `current_directory` variable is updated accordingly.

---

## 🧠 Integration Tip

This command doesn’t return output but sets internal state — it’s best used **before running commands** like `ls`, `cat`, or `download` if those commands take relative paths.

---

## ✅ Supported Platforms

- ✅ Linux
- ✅ Windows
- ✅ macOS


---

## 🔐 Permissions

- Does **not** require administrative privileges.
- Target directory must exist and be accessible by the agent.

---


