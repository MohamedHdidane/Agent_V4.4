# 📖 `pip_freeze` Command – List Installed Python Packages

The `pip_freeze` command programmatically lists all **Python packages installed** on the remote system. Useful for identifying available libraries, dependencies, or potential tools available to the agent.

---

## 🧾 Arguments

| Argument | Type | Description                | Required |
|----------|------|----------------------------|----------|
| _None_   | —    | No arguments are required. | ❌ No    |

---

## 💻 Usage Examples

```bash
pip_freeze
```

- Outputs a full list of installed Python packages and their versions.
- Equivalent to `pip freeze`, but uses multiple fallback methods to ensure compatibility.

---

## 🔁 Behavior

Attempts to retrieve installed packages using the following methods, in order:

1. **`pkg_resources.working_set`** (preferred)
2. **`pip._internal.operations.freeze.freeze()`**
3. **`pkgutil.iter_modules()`** as a last resort (no version info)

If all methods fail, a warning message is displayed.

> 📦 The output is formatted as:
```
package1==1.0.0  
package2==2.3.4  
...
```

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
- Requires Python to have access to `pkg_resources`, `pip`, or `pkgutil`.

---

