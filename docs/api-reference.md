# REST API & Authentication Specification

Go Port Forwarder provides a complete set of RESTful APIs for managing forwarding rules, temporary IP whitelists, and duplicate request audit logs. All API endpoints run on the configured `admin_addr` (e.g., `127.0.0.1:9090`).

---

## 1. Authentication Mechanisms

The service supports **dual authentication** to serve both browser-based Web UI sessions and automated script/API clients.

### 1.1 Cookie Session Authentication (Web UI)
After logging in via `/login`, the server returns a `session_id` cookie:
```http
Set-Cookie: session_id=<crypto-random-hex>; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
```
Subsequent requests automatically include this cookie. Sessions are valid for 24 hours.

### 1.2 HTTP Basic Authentication (API & Scripts)
For curl, Postman, or script automation, credentials can be passed via HTTP headers:
```http
Authorization: Basic <Base64(username:password)>
```

> **Note**: If `username` and `password` under `basic_auth` are omitted or left blank in `config.yml`, authentication is disabled and APIs are publicly accessible.

### 1.3 Smart 401 Header Suppression
When an unauthenticated request accesses `/api/` endpoints:
- If requested by a browser (contains `Accept: text/html` or fetch request), the server returns HTTP 401 **without** `WWW-Authenticate` header to prevent browser native dialog popups.
- For non-browser HTTP clients, the server returns `WWW-Authenticate: Basic realm="API Access"`.

---

## 2. Client IP Resolution Priority

When calling endpoints like `/api/allow` or `/api/ip`, `getClientIP()` extracts the remote IP using the following priority order:

1. **`allow-ip` Header**: High priority header for explicitly overriding or specifying target client IP.
2. **`X-Real-IP` Header**: Set by reverse proxies (Nginx, Traefik).
3. **`X-Forwarded-For` Header**: Extracts the first IP in a comma-separated list.
4. **`RemoteAddr`**: Fallback to underlying TCP connection IP.

---

## 3. API Endpoints

### 3.1 Authentication APIs

#### 3.1.1 Login Page & API (`GET /login`, `POST /login`, `POST /api/login`)
- **GET Request**: Renders embedded login UI (`login.html`), `Content-Type: text/html; charset=utf-8`.
- **POST Request Format**: `application/json`
- **POST Request Body**:
  ```json
  {
    "username": "admin",
    "password": "your_password"
  }
  ```
- **POST Response**:
  - `200 OK`: Sets `session_id` cookie, returns text `"Login successful"`.
  - `401 Unauthorized`: Returns text `"Invalid username or password"`.

#### 3.1.2 Logout (`POST /api/logout`)
- **Request Format**: None
- **Response**: `200 OK`, clears session in memory and resets cookie, returns `"Logout successful"`.

---

### 3.2 Configuration & Rules APIs

#### 3.2.1 Get Configuration (`GET /api/config`)
- **Auth Required**: Yes
- **Response Format**: `application/json`
- **Response Example**:
  ```json
  {
    "admin_addr": "127.0.0.1:9090",
    "basic_auth": {
      "username": "admin",
      "password": "password"
    },
    "temp_ip_pool_size": 10,
    "forwards": [
      {
        "protocols": ["tcp", "udp"],
        "from": "0.0.0.0:5353",
        "to": "8.8.8.8:53",
        "allowed_ips": ["127.0.0.1/32", "192.168.1.0/24"]
      }
    ]
  }
  ```

#### 3.2.2 Reload Configuration (`POST /api/config`)
- **Auth Required**: Yes
- **Request Format**: `application/json` (full `Config` object)
- **Behavior**: Runs port availability check. If successful, writes `config.yml` and hot-reloads services. On failure, rolls back to previous configuration.
- **Response**: `200 OK` text `"Config saved and reloaded successfully."`

---

### 3.3 Dynamic IP Whitelist APIs

#### 3.3.1 Add IP to Temporary Pool (`POST /api/allow`)
Adds the client IP (or `allow-ip` header IP) to the temporary IP pool.

- **Auth Required**: Yes
- **Optional Header**: `x-request-id: <unique-id>` (for anti-replay deduplication)
- **Behavior**:
  - If `x-request-id` is provided:
    - Checks SQLite `request_ids` table.
    - If ID exists: logs entry to `duplicate_requests`, **rejects addition to IP pool**, and returns `200 OK` with text `"Old IP Reseted"`.
    - If ID is new: saves `x-request-id` to database and proceeds to add IP.
  - Adds IP to `TempIPPool`:
    - New IP: returns `200 OK` text `"New IP Added"`.
    - Existing IP: updates timestamp, moves IP to latest position, returns `200 OK` text `"Old IP Reseted"`.

#### 3.3.2 Remove Temporary IP (`POST /api/remove-temp-ip`)
- **Auth Required**: Yes
- **Request Body**:
  ```json
  {
    "ip": "192.168.1.100"
  }
  ```
- **Response**:
  - `200 OK`: `"Successfully removed 192.168.1.100 from temporary whitelist"`
  - `404 Not Found`: IP not found in pool

#### 3.3.3 Add Client `/24` Subnet to Rules (`POST /api/allow-my-ip`)
- **Auth Required**: Yes
- **Behavior**: Calculates client IP's `/24` CIDR subnet (e.g. `192.168.1.0/24`), appends it to `allowed_ips` across all forward rules in `config.yml`, and triggers a hot reload.
- **Response**: `200 OK` text `"Successfully added 192.168.1.0/24 to all rules."`

#### 3.3.4 Get Client IP (`GET /api/ip`)
- **Auth Required**: Yes
- **Response Example**:
  ```json
  {
    "ip": "203.0.113.195"
  }
  ```

#### 3.3.5 Get IP Pool Status (`GET /api/ip-pool`)
- **Auth Required**: Yes
- **Response Example**:
  ```json
  {
    "ips": [
      {
        "ip": "1.1.1.1",
        "last_triggered": "2026-07-28T10:00:00Z"
      }
    ],
    "currentSize": 1,
    "maxSize": 10
  }
  ```

---

### 3.4 Duplicate Request Audit Log APIs

#### 3.4.1 Get Duplicate Requests (`GET /api/duplicate-requests`)
- **Auth Required**: Yes
- **Response Example**:
  ```json
  {
    "count": 1,
    "duplicates": [
      {
        "id": 1,
        "request_id": "req-123456",
        "client_ip": "198.51.100.5",
        "attempted_at": "2026-07-28 14:30:00"
      }
    ]
  }
  ```

#### 3.4.2 Delete Duplicate Request Log (`POST /api/delete-duplicate-request`)
- **Auth Required**: Yes
- **Request Body**: `{"id": 1}`
- **Response**: `200 OK` text `"Duplicate request deleted successfully"`

#### 3.4.3 Clear All Duplicate Request Logs (`POST /api/clear-all-duplicates`)
- **Auth Required**: Yes
- **Response**: `200 OK` text `"Successfully cleared N duplicate request records"`

---

## 4. Static & PWA Routes

| Route | Content-Type | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/` | `text/html` | Required | Main Web Admin UI (`index.html`) |
| `/login` | `text/html` | None | Login Web UI (`login.html`) |
| `/duplicates` | `text/html` | Required | Duplicate Requests Audit UI (`duplicates.html`) |
| `/manifest.json` | `application/json` | None | PWA Web Manifest |
| `/service-worker.js` | `application/javascript` | None | PWA Service Worker |
| `/browserconfig.xml` | `application/xml` | None | Windows Tile Config |
| `/shield-icon.svg` | `image/svg+xml` | None | Shield Icon |
