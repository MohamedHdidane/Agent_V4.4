# 📖 `sleep` Command – Adjust Callback Interval

The `sleep` command sets the agent's **beacon interval** (sleep time) and optional **jitter** percentage. This controls how frequently the agent checks in with the C2 server, useful for **evasion and traffic obfuscation**.

---

## 🧾 Arguments

| Argument  | Type   | Description                                        | Required |
|-----------|--------|----------------------------------------------------|----------|
| `seconds` | `int`  | Number of seconds to wait between callbacks        | ✅ Yes   |
| `jitter`  | `int`  | Optional: Percentage of `seconds` to randomize     | ❌ No    |

---

## 💻 Usage Examples

```bash
sleep 60
sleep 60 30
sleep {"seconds": 90, "jitter": 20}
```

- The `jitter` introduces randomness in callback timing.
- Accepts either raw arguments or a JSON string.

---

## 🔁 Behavior

- Sets agent sleep time (`Sleep`) in seconds.
- If jitter is provided, sets the jitter percentage (`Jitter`).
- If jitter is `-1`, it is ignored.
- Callback sleep info is updated via `SendMythicRPCCallbackUpdate`.

> ⚠️ **Jitter adds randomness** up to the specified % of sleep interval.  
> Example: `sleep 60 30` results in a random sleep between 42–78 seconds.

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  



---

## 🔐 Permissions

- Does **not** require administrative privileges.  
- Agent must be running and connected to apply this setting.

---

