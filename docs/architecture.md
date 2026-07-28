# System Architecture & Core Design

This document details the software architecture, forwarding engine, concurrency model, and resource safety mechanisms of **Go Port Forwarder**.

---

## 1. Architectural Overview

The application follows a modular, single-process, multi-threaded (Goroutine) architecture split into four main subsystems: **Network Forwarding Engine**, **Access Control & IP Pools**, **Web/API Admin Service**, and **Embedded Storage**.

```
                       ┌─────────────────────────┐
                       │   Network Traffic       │
                       │     (TCP / UDP)         │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   IP Access Filter      │
                       │(Static CIDR + Temp Pool)│
                       └────────────┬────────────┘
                                    │ Allowed
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │                   ForwarderManager                     │
       │  ┌───────────────────────┐  ┌───────────────────────┐ │
       │  │     TCP Handler       │  │   UDP Session Manager │ │
       │  │ (handleTCP/forwardTCP)│  │  (UDPSessionManager)  │ │
       │  └───────────────────────┘  └───────────────────────┘ │
       └────────────────────────────┬───────────────────────────┘
                                    │ Forwarding
                                    ▼
                       ┌─────────────────────────┐
                       │      Target Host        │
                       └─────────────────────────┘

 ─────────────────────────────────────────────────────────────────

                       ┌─────────────────────────┐
                       │    Admin / Client HTTP  │
                       └────────────┬────────────┘
                                    │ API / Web UI
                                    ▼
                       ┌─────────────────────────┐
                       │    Web/API Service      │
                       │ (HTTP Server + Dual Auth│
                       └─────┬──────────────┬────┘
                             │              │
                             ▼              ▼
                 ┌───────────────┐      ┌─────────────────┐
                 │ TempIPPool    │      │ SQLite Database │
                 │ (ip_pool.json)│      │ (requests.db)   │
                 └───────────────┘      └─────────────────┘
```

---

## 2. Core Components & Data Structures

### 2.1 Forwarder Manager (`ForwarderManager`)

`ForwarderManager` manages the lifecycle of all active TCP listeners and UDP sockets.

```go
type ForwarderManager struct {
    mu              sync.Mutex
    runningForwards []*runningForwarder
    currentForwards []Forward
    wg              sync.WaitGroup
}
```

- **Mutex Protection (`sync.Mutex`)**: Prevents race conditions during config reloads and service shutdown.
- **Context-Bound Tasks (`runningForwarder`)**: Each forwarder runs under a dedicated `context.CancelFunc` to support graceful shutdown and hot-reloading.
- **Task Synchronization (`sync.WaitGroup`)**: Ensures all background forwarding Goroutines terminate before resources are released or re-allocated.

### 2.2 Dynamic Temporary IP Pool (`TempIPPool`)

`TempIPPool` maintains a capacity-bounded whitelist of transient client IPs using a **Slice + Map** structure for $O(1)$ lookups and FIFO/LRU eviction.

```go
type TempIPPool struct {
    mu       sync.RWMutex
    ips      []TempIPEntry           // Ordered FIFO queue with timestamps
    ipMap    map[string]*TempIPEntry // Fast pointer lookup
    maxSize  int                     // Capacity limit (from config.yml)
    filePath string                  // Storage file path (ip_pool.json)
}
```

- **FIFO/LRU Eviction**: When a new IP is added and capacity (`maxSize`) is reached, the oldest IP is evicted. If an existing IP is triggered, its `LastTriggered` timestamp is updated and it moves to the end of the queue.
- **Persistence**: Modifications are synchronized to `ip_pool.json`, and state is flushed upon program termination via `Shutdown()`.

### 2.3 UDP Session Manager (`UDPSessionManager`)

To prevent memory leaks from connectionless UDP traffic, the application uses a dedicated session manager.

```go
type UDPSessionManager struct {
    mu          sync.RWMutex
    sessions    map[string]*udpSession
    maxSessions int           // Default limit: 1000
    timeout     time.Duration // Default timeout: 5 minutes
}

type udpSession struct {
    conn       *net.UDPConn
    lastActive time.Time
    cancel     context.CancelFunc
}
```

- **LRU Eviction**: Caps max active UDP sessions at `1000`. When reached, the oldest inactive session is closed (`cancel()` + `conn.Close()`).
- **Periodic Cleanup**: A background Goroutine runs every `1 minute` to purge sessions inactive for longer than 5 minutes.

---

## 3. Network Forwarding Mechanics

### 3.1 TCP Forwarding (`handleTCP` & `forwardTCP`)

TCP forwarding utilizes bidirectional stream copying (`io.Copy`):

1. **Accept Connection**: Listener accepts incoming TCP connections.
2. **Access Control**: Validates client IP against `isIPAllowed()`. Unallowed connections are closed immediately.
3. **Target Dialing & Goroutine Pair**: Establishes connection to target (`net.Dial("tcp", to)`). Spawns two Goroutines for bidirectional copy:
   - Client $\rightarrow$ Target (`io.Copy(target, conn)`)
   - Target $\rightarrow$ Client (`io.Copy(conn, target)`)
4. **Synchronization**: Uses `context.WithCancel` and a `done` channel. When either direction finishes or errors out, both sockets close cleanly.

### 3.2 UDP Forwarding (`handleUDP`)

1. **Read Datagram**: Listener reads UDP packets.
2. **Session Lookup**: Looks up client address key (`clientAddr.String()`) in `UDPSessionManager`.
3. **Session Creation**: For new clients, dials a dedicated target UDP socket (`net.DialUDP`) and spawns a Goroutine to handle responses back to the client.
4. **Activity Update**: Updates session `lastActive` timestamp on bidirectional packet flow.

---

## 4. Hot Reloading & Port Check Rollback

When a configuration update is submitted via Web UI or API, `reloadConfigAndForwarders` performs a safe hot reload:

```
 [New Config Received] ──> Lock Manager ──> Stop Current Forwarders
                                                 │
                                                 ▼
 [Rollback Old Config] <── [Port Check Failed] <── Check Port Availability
       │                                         │
       │                                         ▼ [All Ports Free]
       │                                Write config.yml
       │                                         │
       └─────────────────────────────────────────┴──> Start New Forwarders ──> Unlock
```

1. **Port Availability Check (`checkPortsAvailability`)**: Tests port bindings (`net.Listen` / `net.ListenUDP`) for all target `from` addresses before applying new rules.
2. **Atomic Rollback**: If any port is occupied, the reload fails and automatically restores previous forwarders.

---

## 5. Storage & Safety Mechanisms

### 5.1 Embedded SQLite Database (`requests.db`)

Used for anti-replay deduplication (`x-request-id`) and audit logging.

- **Connection Pool**:
  ```go
  db.SetMaxOpenConns(25)
  db.SetMaxIdleConns(5)
  db.SetConnMaxLifetime(5 * time.Minute)
  db.SetConnMaxIdleTime(1 * time.Minute)
  ```
- **Automated Retention & Disk Compaction**:
  - Background task `startDatabaseCleanup` runs every `24 hours` to purge records older than 30 days (`dbDataRetentionDays = 30`).
  - Executes `VACUUM` post-cleanup to reclaim disk space.

### 5.2 HTTP Session Cleanup

- **Session Expiration**: Web UI sessions expire after `24 hours` (`sessionMaxAge = 24h`).
- **Periodic Cleanup**: Background task runs every `30 minutes` to purge expired sessions from memory.

### 5.3 Graceful Shutdown

Upon receiving `SIGINT` or `SIGTERM`:
1. Context cancellation stops background cleanup tasks.
2. SQLite database connections are closed.
3. `tempIPPool.Shutdown()` flushes state to `ip_pool.json`.
4. `manager.StopAll()` terminates active forwarder tasks and releases socket ports.
