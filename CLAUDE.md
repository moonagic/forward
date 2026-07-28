# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development & Build Commands

- **Build**: `make build` (compiles to `bin/forward` with stripped symbols `-ldflags="-s -w"`)
- **Run (Development)**: `make run` or `go run .`
- **Tidy Dependencies**: `make tidy` or `go mod tidy`
- **Clean**: `make clean`
- **Test**: `go test ./...` (run a specific test: `go test -v -run TestName ./...`)
- **Lint & Vet**: `go vet ./...`

## Core Architecture & Key Concepts

This project is a dynamic, single-binary Go application (`forward`) providing TCP & UDP network port forwarding with an embedded web management UI and REST APIs.

### Main Components (`main.go`)

- **Embedded Frontend Assets**: Web interfaces (`index.html`, `login.html`, `duplicates.html`, etc.) are compiled directly into the binary using Go's `//go:embed` directives.
- **Forwarder Manager (`ForwarderManager`)**: Controls TCP listeners (`net.Listener`) and UDP sockets (`net.UDPConn`). Handles dynamic live updates (hot reloading) of forwarding rules without restarting the application process.
- **Access Control & IP Pools**:
  - **Static Whitelisting**: CIDR notation configured per forwarding rule (`allowed_ips`).
  - **Temporary IP Pool (`TempIPPool`)**: FIFO/LRU dynamic pool allowing transient client IPs. Persisted across restarts via `ip_pool.json`.
- **UDP Session Management (`UDPSessionManager`)**: Tracks connectionless UDP sessions per remote endpoint, imposing max session limits (`udpMaxSessions`) and automatic inactivity cleanup routines (`udpCleanupInterval`) to prevent memory leaks.
- **Authentication**: Dual mechanism supporting cookie-based session management for the Web UI and HTTP Basic Auth for API/automation requests (configured in `config.yml`).
- **Database & Storage (`requests.db`)**: Embedded SQLite database initialized at startup. Tracks request IDs and duplicate request logs with connection pooling and a background goroutine for automatic 30-day retention cleanup.

### Key Operational Files

- `config.yml` (template: `config.example.yml`): Stores admin address, credentials, temp pool size, and forwarding rules.
- `ip_pool.json`: Auto-generated persistent storage for the dynamic temporary IP pool.
- `requests.db`: SQLite database for logging duplicate requests and request IDs.
- `forwarder.service`: Systemd service template for Linux deployments.
