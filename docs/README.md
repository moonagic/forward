# Go Port Forwarder Documentation

Welcome to the official technical documentation for **Go Port Forwarder (`forward`)**. This application is a dynamic, high-performance TCP/UDP port forwarding service written in Go, featuring an embedded glassmorphism Web UI, SQLite audit logging, a dynamic temporary IP whitelist pool, and smooth hot-reloading capabilities.

---

## 📚 Documentation Index

The documentation is organized into four core modules:

### 1. [Architecture & System Design (architecture.md)](./architecture.md)
Detailed breakdown of system architecture, core component designs, network packet forwarding mechanisms, concurrency models, Goroutine lifecycle management, and resource protection strategies (LRU eviction, connection pooling, and automated database cleanup).

### 2. [REST API & Authentication Specification (api-reference.md)](./api-reference.md)
Complete specification of all RESTful API endpoints for the Web UI and automation scripts, including dual authentication (Session Cookie & HTTP Basic Auth), client IP resolution priority, and anti-replay request deduplication.

### 3. [Configuration & Persistence (configuration.md)](./configuration.md)
Full guide to `config.yml` schema, dynamic IP pool persistence (`ip_pool.json`), and SQLite embedded database schemas (`requests.db`) with 30-day automatic data retention.

### 4. [Deployment & Operations Guide (deployment.md)](./deployment.md)
Production deployment guidelines, Systemd service setup, single-binary compilation (`//go:embed`), security best practices, and troubleshooting tips.

---

## ⚡ Quick Overview

- **Language**: Go 1.16+
- **Database**: SQLite 3 (via `github.com/mattn/go-sqlite3`)
- **Distribution**: Single binary with embedded Web UI & assets (`//go:embed`)
- **Configuration**: YAML (`gopkg.in/yaml.v3`)
