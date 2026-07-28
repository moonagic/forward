# Configuration & Persistence Specification

This document describes the structure of `config.yml`, persistent storage files, and SQLite database schemas.

---

## 1. Main Configuration File (`config.yml`)

The application loads `config.yml` from the working directory at startup.

### 1.1 Complete Configuration Example (`config.example.yml`)

```yaml
# Admin Web UI and REST API listening address.
admin_addr: "127.0.0.1:9090"

# Authentication credentials for Web UI and API.
basic_auth:
  username: "admin"
  password: "password"

# Size limit for the temporary IP whitelist pool (default: 10).
temp_ip_pool_size: 10

# Forwarding rules list.
forwards:
  # Example 1: TCP & UDP DNS forwarding with CIDR whitelist
  - protocols: ["tcp", "udp"]
    from: "0.0.0.0:5353"
    to: "8.8.8.8:53"
    allowed_ips:
      - "127.0.0.1/32"
      - "192.168.1.0/24"

  # Example 2: TCP Web server forwarding (allows all IPs)
  - protocols: ["tcp"]
    from: "0.0.0.0:8080"
    to: "127.0.0.1:80"
    allowed_ips: []
```

### 1.2 Field Specification

| Field Name | Type | Required | Default | Description |
| :--- | :--- | :---: | :--- | :--- |
| `admin_addr` | string | Yes | None | Web UI and REST API host/port (e.g., `"0.0.0.0:9090"`). If omitted, admin server will not start. |
| `basic_auth.username` | string | No | `""` | Admin username. If blank, authentication is disabled. |
| `basic_auth.password` | string | No | `""` | Admin password. If blank, authentication is disabled. |
| `temp_ip_pool_size` | int | No | `10` | Maximum capacity for dynamic temporary IP pool. Uses FIFO/LRU eviction when full. |
| `forwards` | array | No | `[]` | Array of port forwarding rules. |
| `forwards[].protocols` | string[] | Yes | None | Protocols to forward: `"tcp"`, `"udp"`, or `["tcp", "udp"]`. |
| `forwards[].from` | string | Yes | None | Local listen address and port (e.g., `"0.0.0.0:8080"`). |
| `forwards[].to` | string | Yes | None | Destination target address and port (e.g., `"192.168.1.100:80"`). |
| `forwards[].allowed_ips` | string[] | No | `[]` | Static CIDR whitelist (e.g., `["192.168.1.0/24"]`). **If empty or omitted, all client IPs are permitted.** |

---

## 2. Dynamic IP Pool Persistence (`ip_pool.json`)

When temporary IPs are added or triggered via API (`/api/allow`), state is serialized to `ip_pool.json` to persist across service restarts.

### 2.1 JSON Schema Example

```json
{
  "ips": [
    {
      "ip": "203.0.113.45",
      "last_triggered": "2026-07-28T18:30:00.123456789+08:00"
    },
    {
      "ip": "198.51.100.12",
      "last_triggered": "2026-07-28T18:35:10.987654321+08:00"
    }
  ]
}
```

### 2.2 Lifecycle & Ordering
- **Queue Order**: The last item in the array represents the most recently added or triggered IP.
- **Timestamp Refresh**: When an existing temporary IP matches incoming TCP/UDP traffic, `last_triggered` updates and the entry moves to the end of the queue.
- **Eviction**: When total IPs exceed `temp_ip_pool_size`, index `0` (oldest) is evicted.

---

## 3. SQLite Database Schema (`requests.db`)

Embedded SQLite database `requests.db` stores request IDs for anti-replay verification and logs duplicate request attempts.

### 3.1 `request_ids` Table Schema
Stores valid processed Request IDs.

```sql
CREATE TABLE IF NOT EXISTS request_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### 3.2 `duplicate_requests` Table Schema
Logs duplicate request attempts for security auditing.

```sql
CREATE TABLE IF NOT EXISTS duplicate_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### 3.3 Data Retention & Disk Compaction

- **Retention Period**: Global configuration `dbDataRetentionDays = 30` (retains records from the last 30 days).
- **Cleanup Interval**: Background task runs every `24 hours` (`dbCleanupInterval`):
  ```sql
  DELETE FROM request_ids WHERE created_at < ?;
  DELETE FROM duplicate_requests WHERE attempted_at < ?;
  ```
- **Automatic VACUUM**: Automatically executes SQLite `VACUUM` after successful record deletions to reclaim disk space.
