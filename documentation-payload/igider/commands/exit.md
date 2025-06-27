# ❌ `exit` Command – Terminate Agent Process

The `exit` command forcefully terminates the **current agent process**. This is useful when cleaning up a session, evading detection, or gracefully ending a tasking lifecycle.

---

## 🚫 Arguments

This command **does not require any arguments**.


---

## 💻 Usage Example

```bash
exit
```

- Once executed, the agent process will shut down and **disconnect from the Mythic C2 server**.
- It is **not recoverable** unless a persistence mechanism is in place.

---

## 🔁 Behavior

- Calls `os._exit(0)` to immediately terminate the Python process.
- Skips cleanup logic or exception handling.
- Can be used when:
  - Cleaning up after execution
  - Testing agent lifecycle behavior
  - Leaving no trace by killing the session

---

## 📌 Command Attributes

- ❌ No admin privileges required
- 🧠 Logic-free command, safe for any operator
- 🔒 Disconnects agent silently

---



## ✅ Supported Platforms

- ✅ Linux
- ✅ Windows
- ✅ macOS



---

