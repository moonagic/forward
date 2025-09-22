# Go Port Forwarder

A dynamic, API-driven port forwarder with a web UI, written in Go.

This tool allows you to forward network ports (TCP/UDP) based on a YAML configuration file. It features a modern web interface to manage the configuration in real-time without restarting the service.

## Features

- **Dynamic Configuration**: Manage forwarding rules via a simple `config.yml` file.
- **TCP & UDP Support**: Forward both TCP and UDP traffic, configurable for each rule.
- **Modern Web Interface**: A clean, responsive web UI with glassmorphism design to view, add, edit, and delete forwarding rules.
- **Hot Reloading**: Configurations can be changed and applied instantly from the web UI without any service interruption.
- **IP Whitelisting**: Restrict access to forwarded ports by specifying allowed source IP ranges (CIDR notation) for each rule.
- **Temporary IP Pool**: Dynamic IP management with persistent storage - temporarily allow IPs that survive service restarts.
- **Session-Based Authentication**: Modern login system with secure session management and dual authentication support (sessions + Basic Auth).
- **Configurable Pool Size**: Customize temporary IP pool size via configuration file.
- **Dark/Light Mode**: The web UI includes a theme switcher with full responsive design for desktop and mobile.
- **Single-Binary Deployment**: The web interface is embedded into the Go binary, making deployment as simple as copying a single file.
- **Systemd Service**: A `forwarder.service` file is provided for easy deployment as a background service on Linux.

## Getting Started

### Prerequisites

- Go 1.16 or later (due to the use of the `embed` package).

### Configuration

The application is configured using the `config.yml` file in the same directory.

```yaml
# The address where the admin web UI will be served.
admin_addr: "127.0.0.1:9090"

# Authentication credentials for the web interface and API.
basic_auth:
  username: "admin"
  password: "password"

# Size of the temporary IP pool (default: 10 if not specified).
temp_ip_pool_size: 10

# A list of forwarding rules.
forwards:
  # This rule forwards both TCP and UDP traffic for DNS.
  - protocols: ["tcp", "udp"]
    from: "0.0.0.0:5353"
    to: "8.8.8.8:53"
    allowed_ips:
      - "127.0.0.1/32"
      - "192.168.1.0/24"

  # This rule forwards only TCP traffic for a web server.
  - protocols: ["tcp"]
    from: "0.0.0.0:8080"
    to: "127.0.0.1:80"
    # If allowed_ips is empty or omitted, all source IPs are allowed.
    allowed_ips: []
```

### Building and Running

A `Makefile` is provided to simplify common tasks.

**To build the binary:**

This will compile the application into a single executable file named `forwarder`.

```bash
make build
```

**To run the application for development:**

This command will compile and run the application directly.

```bash
make run
```

Once running, the forwarding service will be active, and the web UI will be available at the address specified by `admin_addr` in your config. You'll be prompted to log in using the credentials specified in the `basic_auth` section of your configuration.

### Key Features Usage

**Temporary IP Pool**: The web interface includes a temporary IP management section where you can:
- Add IP addresses that need temporary access to forwarded ports
- View currently allowed temporary IPs with visual priority indicators
- Remove IPs when access is no longer needed
- IPs added to the temporary pool are automatically saved to `ip_pool.json` and persist across service restarts

**Authentication**: The application supports dual authentication:
- **Web Interface**: Modern session-based login with secure cookie management
- **API Access**: HTTP Basic Auth for programmatic access and automation scripts

**Responsive Design**: The web interface features a modern glassmorphism design that works seamlessly on desktop and mobile devices with theme switching support.

## Deployment as a Systemd Service

A `forwarder.service` file is included for running the application as a managed service on modern Linux systems.

1.  Place the compiled `forwarder` binary and your `config.yml` file into a directory like `/opt/forwarder`.
2.  Copy the `forwarder.service` file to `/etc/systemd/system/`.
3.  Follow the instructions within the comments of the `.service` file to create a dedicated user and set permissions.
4.  Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now forwarder.service
```

## Makefile Commands

- `make build`    - Build the application for production.
- `make run`      - Run the application for development.
- `make clean`    - Clean build artifacts.
- `make tidy`     - Tidy Go module dependencies.
- `make help`     - Show this help message.
