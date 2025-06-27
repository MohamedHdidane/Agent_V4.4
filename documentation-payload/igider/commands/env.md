# 📖 `env` Command – Environment Variable Dumper

The `env` command retrieves and returns all **environment variables** from the agent's running context. This is often used for post-exploitation to discover sensitive configuration details, user profiles, proxy settings, or credential-related data stored in environment variables.

---

## 🧾 Arguments

| Argument | Type   | Description                       | Required |
|----------|--------|-----------------------------------|----------|
| _None_   | —      | This command takes no arguments.  | ❌ No    |

---

## 💻 Usage Examples

```bash
env
```

- Outputs all current environment variables in `KEY: VALUE` format.
- Useful for gathering context or credentials during post-exploitation.

---

## 🔁 Behavior

- Calls Python's `os.environ` to enumerate all available environment variables.
- Formats them line-by-line as `KEY: VALUE`.
- No filtering or transformation is applied — raw values are returned.
- Does **not** modify the environment.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                                  |
|--------------|---------------------------------------|
| T1082        | System Information Discovery          |
| T1552.007    | Credentials in Environment Variables  |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  


---

## 🔐 Permissions

- Does **not** require administrative privileges.
- Agent must have permission to access the process environment.

---


