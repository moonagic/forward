# Deployment, Operations & Development Guide

This guide covers building, deploying via Systemd on Linux, security best practices, and troubleshooting tips for Go Port Forwarder.

---

## 1. Building the Application

### 1.1 Prerequisites
- **Go Compiler**: Go 1.16 or higher (uses `//go:embed`).
- **CGO Toolchain**: Requires `CGO_ENABLED=1` and GCC compiler for SQLite 3 (`github.com/mattn/go-sqlite3`).

### 1.2 Using Makefile

The project includes a `Makefile` for common tasks:

```bash
# Build executable (output: bin/forward with stripped symbols)
make build

# Run application directly (development)
make run

# Tidy Go module dependencies
make tidy

# Clean build artifacts
make clean
```

The output binary `bin/forward` embeds all Web UI templates (`index.html`, `login.html`, `duplicates.html`) and static assets (`//go:embed`), enabling **single-file distribution**.

---

## 2. Production Deployment via Systemd

Recommended setup on Linux (Ubuntu, Debian, CentOS, RHEL).

### 2.1 Step-by-Step Installation

1. **Create Unprivileged System User**:
   ```bash
   sudo useradd --system --no-create-home --shell /bin/false forwarder-user
   ```

2. **Setup Directories & Binary**:
   ```bash
   # Create directory for binary & configuration
   sudo mkdir -p /etc/forwarder
   
   # Copy executable to path
   sudo cp bin/forward /usr/local/bin/forwarder
   sudo chmod +x /usr/local/bin/forwarder

   # Copy configuration file
   sudo cp config.example.yml /etc/forwarder/config.yml
   
   # Set ownership
   sudo chown -R forwarder-user:forwarder-user /etc/forwarder
   ```

3. **Install Systemd Unit**:
   Copy `forwarder.service` template to systemd directory:
   ```bash
   sudo cp forwarder.service /etc/systemd/system/forwarder.service
   ```

   **Service File (`forwarder.service`)**:
   ```ini
   [Unit]
   Description=Go Port Forwarder Service
   After=network-online.target
   Wants=network-online.target

   [Service]
   User=forwarder-user
   Group=forwarder-user
   WorkingDirectory=/etc/forwarder
   ExecStart=/usr/local/bin/forwarder
   Restart=on-failure
   RestartSec=5s
   LimitNOFILE=65536
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   ```

4. **Enable & Start Service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now forwarder.service
   ```

5. **Monitor Logs**:
   ```bash
   # Check service status
   sudo systemctl status forwarder.service

   # View live journal logs
   sudo journalctl -u forwarder.service -f
   ```

---

## 3. Production Security Best Practices

### 3.1 Privileges & Capabilities
- **Non-Root Execution**: Run as an unprivileged user whenever forwarding non-privileged ports (> 1024).
- **Binding Privileged Ports (< 1024)**: If forwarding ports like 80, 443, or 53, assign Linux capabilities rather than running as root:
  ```bash
  sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/forwarder
  ```

### 3.2 Web UI Reverse Proxy & HTTPS
In production, set `admin_addr` to `127.0.0.1:9090` and place the Web UI behind Nginx or Caddy with TLS/HTTPS enabled.

**Nginx Configuration Example**:
```nginx
server {
    listen 443 ssl http2;
    server_name forwarder.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 4. Troubleshooting

### 4.1 "One or more ports are unavailable, exiting."
- **Cause**: Target port defined in `from` is already bound by another process (Nginx, dnsmasq, etc.).
- **Fix**: Check port usage with `netstat -tlpn` or `lsof -i :<port>`, or update port numbers in `config.yml`.

### 4.2 Temporary IP Whitelist Not Taking Effect
- **Cause**: Client IP recognized by server differs from client's actual public IP due to proxy/NAT.
- **Troubleshoot**: Check logs when calling `/api/allow`:
  `Added new client IP x.x.x.x to temporary IP pool`
- **Fix**: Pass explicit IP via `allow-ip: <IP>` header if needed.

### 4.3 SQLite Database Permission Error
- **Cause**: Application lacks write permission in `WorkingDirectory`.
- **Fix**: Grant ownership to the service user:
  ```bash
  sudo chown -R forwarder-user:forwarder-user /etc/forwarder
  ```
