# 📖 `eval_code` Command – Python Code Evaluator

The `eval_code` command evaluates and executes **arbitrary Python code** within the agent’s runtime context. This can be used for dynamic logic injection, quick calculations, or inspection of the agent environment.

⚠️ **Use with extreme caution.** Arbitrary evaluation introduces significant risks and should be restricted to trusted users and scenarios.

---

## 🧾 Arguments

| Argument   | Type     | Description                            | Required |
|------------|----------|----------------------------------------|----------|
| `command`  | `string` | Python code string to evaluate         | ✅ Yes   |

---

## 💻 Usage Examples

```bash
eval_code "1 + 2"
eval_code "import os; os.getcwd()"
eval_code "sum([i for i in range(10)])"
```

- Multi-line code must be passed as a single line with semicolons (`;`).
- Returns the result of the evaluated expression or last statement.
- Intended for advanced use — behavior depends on the agent's Python environment.

---

## 🔁 Behavior

- Uses Python’s built-in `eval()` function to evaluate the given expression.
- The code is executed **within the context of the agent process**.
- No sandboxing is applied — the code has access to all agent memory and imports.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                      |
|--------------|---------------------------|
| T1059.006     | Command and Scripting Interpreter: Python |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  



---

## 🔐 Permissions

- Does **not** require administrative privileges.
- Can only evaluate code permitted by the current Python interpreter environment.

---



