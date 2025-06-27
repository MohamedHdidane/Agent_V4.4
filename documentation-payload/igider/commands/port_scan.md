
# 📄 `port_scan` Command – Input Format 

The `port_scan` command allows operators to perform TCP port scans on targets. It accepts flexible formats for targets and ports and can be used with or without quotes (though quotes are recommended in scripts).



## ✅ Usage Syntax

```bash
port_scan <target> <ports> [timeout] [threads]
```

- `<target>` *(required)* – IP address, IP range, or CIDR  
- `<ports>` *(required)* – Port or list/range of ports  
- `[timeout]` *(optional)* – Timeout per scan in seconds (default: `1`)  
- `[threads]` *(optional)* – Max concurrent threads (default: `100`)  

---

## 🎯 Accepted `target` Formats

| Format        | Example                        | Description                                      |
|---------------|--------------------------------|--------------------------------------------------|
| Single IP     | `192.168.1.10`                 | Scan a single host                               |
| IP Range      | `192.168.1.10-192.168.1.15`    | Range within same subnet (last octet only)       |
| CIDR Notation | `192.168.1.0/30`               | All usable hosts in the subnet                   |
| Shorthand     | `192.168.1.5-10`               | Same as range; expands from first IP octet group |


---

## 🔌 Accepted `ports` Formats

| Format        | Example              | Description                                      |
|---------------|----------------------|--------------------------------------------------|
| Single Port   | `80`                 | Scan one port                                    |
| Port List     | `22,80,443`          | Comma-separated list of ports                    |
| Port Range    | `20-25`              | Inclusive range of ports                         |
| Mixed Format  | `21,22,80-82,443`    | Any combination of list and range                |

---

## 🕒 Optional Parameters

| Name      | Example | Description                                      |
|-----------|---------|--------------------------------------------------|
| `timeout` | `0.5`   | Per-port timeout in seconds (default: `1`)       |
| `threads` | `200`   | Max concurrent scanning threads (default: `100`) |

---

## ✅ Working Command Examples

| Description                       | Command Example |
|-----------------------------------|------------------|
| Scan single IP on one port        | `port_scan 192.168.1.1 80` |
| Scan IP range with port list      | `port_scan 192.168.1.10-15 22,80,443` |
| CIDR scan with port range         | `port_scan 192.168.1.0/30 20-25` |
| Mixed ports, custom timeout       | `port_scan 10.0.0.5 22,80,443,1000-1005 0.5` |
| Full command with all options     | `port_scan 192.168.1.1 22,80,443 1.5 150` |

---




