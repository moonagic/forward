package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

//go:embed index.html
var indexHTML []byte

//go:embed login.html
var loginHTML []byte

//go:embed manifest.json
var manifestJSON []byte

//go:embed service-worker.js
var serviceWorkerJS []byte

//go:embed browserconfig.xml
var browserconfigXML []byte

//go:embed shield-icon.svg
var shieldIconSVG []byte

const udpTimeout = 5 * time.Minute
const configPath = "config.yml"
const ipPoolPath = "ip_pool.json"
const dbPath = "requests.db"

// --- Data Structures ---

type BasicAuth struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type Config struct {
	AdminAddr      string    `yaml:"admin_addr" json:"admin_addr"`
	BasicAuth      BasicAuth `yaml:"basic_auth" json:"basic_auth"`
	Forwards       []Forward `yaml:"forwards" json:"forwards"`
	TempIPPoolSize int       `yaml:"temp_ip_pool_size" json:"temp_ip_pool_size"`
}

type Forward struct {
	Protocols  []string `yaml:"protocols" json:"protocols"`
	From       string   `yaml:"from" json:"from"`
	To         string   `yaml:"to" json:"to"`
	AllowedIPs []string `yaml:"allowed_ips" json:"allowed_ips"`
}

// TempIPEntry represents a temporary IP with its last trigger time
type TempIPEntry struct {
	IP            string    `json:"ip"`
	LastTriggered time.Time `json:"last_triggered"`
}

// TempIPPool manages a pool of temporarily allowed IPs with FIFO eviction
type TempIPPool struct {
	mu       sync.RWMutex
	ips      []TempIPEntry           // FIFO queue of IPs with metadata
	ipMap    map[string]*TempIPEntry // Fast lookup with pointer to entry
	maxSize  int
	filePath string // Path to persistent storage file
}

type IPPoolData struct {
	IPs []TempIPEntry `json:"ips"`
}

type RemoveIPRequest struct {
	IP string `json:"ip"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Session management
type Session struct {
	ID        string
	CreatedAt time.Time
	LastSeen  time.Time
}

var (
	sessions    = make(map[string]*Session)
	sessionsMux = sync.RWMutex{}
	db          *sql.DB
)

// --- Global Manager ---

var manager = NewForwarderManager()
var tempIPPool *TempIPPool

// --- Database Functions ---

func initDatabase() error {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create request_ids table if it doesn't exist
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS request_ids (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_id TEXT NOT NULL UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	if _, err := db.Exec(createTableQuery); err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	log.Printf("Database initialized: %s", dbPath)
	return nil
}

func isRequestIDExists(requestID string) (bool, error) {
	query := "SELECT COUNT(*) FROM request_ids WHERE request_id = ?"
	var count int
	err := db.QueryRow(query, requestID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func saveRequestID(requestID string) error {
	query := "INSERT INTO request_ids (request_id) VALUES (?)"
	_, err := db.Exec(query, requestID)
	return err
}

func closeDatabase() {
	if db != nil {
		db.Close()
		log.Println("Database connection closed")
	}
}

// --- Temporary IP Pool ---

func NewTempIPPool(maxSize int, filePath string) *TempIPPool {
	pool := &TempIPPool{
		ips:      make([]TempIPEntry, 0, maxSize),
		ipMap:    make(map[string]*TempIPEntry),
		maxSize:  maxSize,
		filePath: filePath,
	}

	// Load existing IPs from file
	if err := pool.loadFromFile(); err != nil {
		log.Printf("Warning: Could not load IP pool from file %s: %v", filePath, err)
	} else {
		log.Printf("IP pool persistence enabled using file: %s", filePath)
	}

	return pool
}

// loadFromFile loads the IP pool from persistent storage
func (pool *TempIPPool) loadFromFile() error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	data, err := os.ReadFile(pool.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, that's OK
			return nil
		}
		return err
	}

	var poolData IPPoolData
	if err := json.Unmarshal(data, &poolData); err != nil {
		return err
	}

	// Rebuild the pool from loaded data
	pool.ips = make([]TempIPEntry, 0, pool.maxSize)
	pool.ipMap = make(map[string]*TempIPEntry)

	for _, entry := range poolData.IPs {
		if len(pool.ips) < pool.maxSize {
			pool.ips = append(pool.ips, entry)
			// Point to the entry in the slice
			pool.ipMap[entry.IP] = &pool.ips[len(pool.ips)-1]
		}
	}

	log.Printf("Loaded %d IPs from persistent storage", len(pool.ips))
	return nil
}

// saveToFile saves the current IP pool to persistent storage
func (pool *TempIPPool) saveToFile() error {
	poolData := IPPoolData{
		IPs: make([]TempIPEntry, len(pool.ips)),
	}
	copy(poolData.IPs, pool.ips)

	data, err := json.MarshalIndent(poolData, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(pool.filePath, data, 0644)
}

func (pool *TempIPPool) Add(ip string) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	var isNewIP = false
	now := time.Now()

	// If IP already exists, move it to the end (most recent) and update timestamp
	if existingEntry, exists := pool.ipMap[ip]; exists {
		// Update the timestamp
		existingEntry.LastTriggered = now

		// Find and remove the existing IP entry
		for i, entry := range pool.ips {
			if entry.IP == ip {
				pool.ips = append(pool.ips[:i], pool.ips[i+1:]...)
				break
			}
		}
		// Add it to the end with updated timestamp
		newEntry := TempIPEntry{IP: ip, LastTriggered: now}
		pool.ips = append(pool.ips, newEntry)
		pool.ipMap[ip] = &pool.ips[len(pool.ips)-1]
		isNewIP = false // IP already existed, just moved to top
	} else {
		// If we're at capacity, remove the oldest IP
		if len(pool.ips) >= pool.maxSize {
			oldestEntry := pool.ips[0]
			pool.ips = pool.ips[1:]
			delete(pool.ipMap, oldestEntry.IP)
		}

		// Add the new IP with current timestamp
		newEntry := TempIPEntry{IP: ip, LastTriggered: now}
		pool.ips = append(pool.ips, newEntry)
		pool.ipMap[ip] = &pool.ips[len(pool.ips)-1]
		isNewIP = true // New IP added
	}

	// Save to file after modification
	if err := pool.saveToFile(); err != nil {
		log.Printf("Warning: Failed to save IP pool to file: %v", err)
	}

	return isNewIP
}

func (pool *TempIPPool) Contains(ip string) bool {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	_, exists := pool.ipMap[ip]
	return exists
}

// UpdateTriggerTime updates the last trigger time for an IP and moves it to the most recent position
func (pool *TempIPPool) UpdateTriggerTime(ip string) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if existingEntry, exists := pool.ipMap[ip]; exists {
		now := time.Now()
		// Update the timestamp
		existingEntry.LastTriggered = now

		// Find and remove the existing IP entry
		for i, entry := range pool.ips {
			if entry.IP == ip {
				pool.ips = append(pool.ips[:i], pool.ips[i+1:]...)
				break
			}
		}
		// Add it to the end with updated timestamp
		newEntry := TempIPEntry{IP: ip, LastTriggered: now}
		pool.ips = append(pool.ips, newEntry)
		pool.ipMap[ip] = &pool.ips[len(pool.ips)-1]

		// Save to file after modification
		if err := pool.saveToFile(); err != nil {
			log.Printf("Warning: Failed to save IP pool to file: %v", err)
		}
	}
}

func (pool *TempIPPool) GetAll() []TempIPEntry {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	result := make([]TempIPEntry, len(pool.ips))
	copy(result, pool.ips)
	return result
}

func (pool *TempIPPool) Remove(ip string) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Check if IP exists
	if _, exists := pool.ipMap[ip]; !exists {
		return false
	}

	// Find and remove the IP from slice
	for i, existingIP := range pool.ips {
		if existingIP.IP == ip {
			pool.ips = append(pool.ips[:i], pool.ips[i+1:]...)
			break
		}
	}

	// Remove from map
	delete(pool.ipMap, ip)

	// Save to file after modification
	if err := pool.saveToFile(); err != nil {
		log.Printf("Warning: Failed to save IP pool to file: %v", err)
	}

	return true
}

// Shutdown gracefully saves the IP pool to file
func (pool *TempIPPool) Shutdown() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if err := pool.saveToFile(); err != nil {
		log.Printf("Warning: Failed to save IP pool during shutdown: %v", err)
	} else {
		log.Printf("IP pool saved successfully during shutdown")
	}
}

// --- Forwarder Manager ---

type runningForwarder struct {
	cancel context.CancelFunc
}

type ForwarderManager struct {
	mu              sync.Mutex
	runningForwards []*runningForwarder
	currentForwards []Forward
	wg              sync.WaitGroup
}

func NewForwarderManager() *ForwarderManager {
	return &ForwarderManager{}
}

func (m *ForwarderManager) StartForwarders(forwards []Forward) {
	// Assumes caller holds the lock
	m.currentForwards = forwards // Save current config for rollback

	log.Println("Starting forwarder tasks...")
	for _, f := range forwards {
		var allowedNets []*net.IPNet
		for _, cidrStr := range f.AllowedIPs {
			_, network, err := net.ParseCIDR(cidrStr)
			if err != nil {
				log.Printf("Error: Failed to parse CIDR '%s' for rule %s: %v. Skipping this rule.", cidrStr, f.From, err)
				continue
			}
			allowedNets = append(allowedNets, network)
		}

		for _, proto := range f.Protocols {
			ctx, cancel := context.WithCancel(context.Background())
			m.wg.Add(1)

			go func(proto string, f Forward, nets []*net.IPNet) {
				defer m.wg.Done()
				log.Printf("Starting forward: %s from %s to %s", strings.ToUpper(proto), f.From, f.To)
				switch proto {
				case "tcp":
					handleTCP(ctx, f.From, f.To, nets)
				case "udp":
					handleUDP(ctx, f.From, f.To, nets)
				default:
					log.Printf("Unknown protocol type: %s", proto)
				}
			}(proto, f, allowedNets)

			m.runningForwards = append(m.runningForwards, &runningForwarder{cancel: cancel})
		}
	}
	log.Println("All forwarder tasks started.")
}

func (m *ForwarderManager) StopAll() {
	// Assumes caller holds the lock, but unlocks internally for Wait()
	log.Println("Stopping all forwarder tasks...")
	for _, f := range m.runningForwards {
		f.cancel()
	}
	m.runningForwards = nil

	m.mu.Unlock()
	m.wg.Wait()
	m.mu.Lock()

	log.Println("All forwarder tasks stopped.")
}

// --- Web Admin Handlers ---

// Session-based authentication
func generateSessionID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

func createSession() string {
	sessionID := generateSessionID()
	if sessionID == "" {
		return ""
	}

	sessionsMux.Lock()
	defer sessionsMux.Unlock()

	now := time.Now()
	sessions[sessionID] = &Session{
		ID:        sessionID,
		CreatedAt: now,
		LastSeen:  now,
	}

	return sessionID
}

func validateSession(sessionID string) bool {
	if sessionID == "" {
		return false
	}

	sessionsMux.Lock()
	defer sessionsMux.Unlock()

	session, exists := sessions[sessionID]
	if !exists {
		return false
	}

	// Check if session is expired (24 hours)
	if time.Since(session.CreatedAt) > 24*time.Hour {
		delete(sessions, sessionID)
		return false
	}

	// Update last seen time
	session.LastSeen = time.Now()
	return true
}

// Dual authentication: supports both session and basic auth
func requireAuth(handler http.HandlerFunc, username, password string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication if username/password not configured
		if username == "" || password == "" {
			handler(w, r)
			return
		}

		// Check for session cookie first
		cookie, err := r.Cookie("session_id")
		if err == nil && validateSession(cookie.Value) {
			handler(w, r)
			return
		}

		// Check for Basic Auth (for API clients)
		user, pass, ok := r.BasicAuth()
		if ok && user == username && pass == password {
			handler(w, r)
			return
		}

		// For API endpoints, return 401 with WWW-Authenticate header
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("WWW-Authenticate", `Basic realm="API Access"`)
			http.Error(w, "Unauthorized. Use Basic Auth or session cookie.", http.StatusUnauthorized)
			return
		}

		// For web pages, redirect to login page
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getConfig(w, r)
	case http.MethodPost:
		postConfig(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func getConfig(w http.ResponseWriter, r *http.Request) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	var adminAddr string
	var basicAuth BasicAuth
	yamlFile, err := os.ReadFile(configPath)
	if err == nil {
		var fileConfig Config
		if yaml.Unmarshal(yamlFile, &fileConfig) == nil {
			adminAddr = fileConfig.AdminAddr
			basicAuth = fileConfig.BasicAuth
		}
	}

	config := Config{
		AdminAddr: adminAddr,
		BasicAuth: basicAuth,
		Forwards:  manager.currentForwards,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func postConfig(w http.ResponseWriter, r *http.Request) {
	var newConfig Config
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := reloadConfigAndForwarders(newConfig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Config saved and reloaded successfully."))
}

// getClientIP extracts the client's IP address from the request, prioritizing proxy headers.
func getClientIP(r *http.Request) string {
	// Check X-Real-IP header first, which is often set by reverse proxies.
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}

	// Then check X-Forwarded-For header.
	if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		// X-Forwarded-For can be a comma-separated list of IPs. The first one is the original client.
		return strings.Split(forwardedFor, ",")[0]
	}

	// Fallback to the standard RemoteAddr.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, it might be just an IP without a port.
		return r.RemoteAddr
	}
	return ip
}

func allowHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for x-request-id header
	requestID := r.Header.Get("x-request-id")
	if requestID != "" {
		// Check if this request ID already exists in the database
		exists, err := isRequestIDExists(requestID)
		if err != nil {
			log.Printf("Database error checking request ID %s: %v", requestID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if exists {
			// Request ID already exists, reject the request
			log.Printf("Request ID %s already exists, rejecting request", requestID)
			// http.Error(w, "Request ID already processed", http.StatusConflict)
			w.Write([]byte("Old IP Reseted"))
			return
		}

		// Save the new request ID to the database
		if err := saveRequestID(requestID); err != nil {
			log.Printf("Database error saving request ID %s: %v", requestID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		log.Printf("Saved new request ID %s to database", requestID)
	}

	// Get client IP directly from request
	ipStr := getClientIP(r)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Could not parse client IP address: "+ipStr, http.StatusBadRequest)
		return
	}

	// Add to temporary IP pool
	isNewIP := tempIPPool.Add(ipStr)

	if isNewIP {
		log.Printf("Added new client IP %s to temporary IP pool", ipStr)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("New IP Added"))
	} else {
		log.Printf("Reset existing client IP %s to most recent in temporary IP pool", ipStr)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Old IP Reseted"))
	}
}

func allowMyIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ipStr := getClientIP(r)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Could not parse IP address: "+ipStr, http.StatusBadRequest)
		return
	}

	// Create /24 subnet
	ipNet := net.IPNet{IP: ip.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
	cidrStr := ipNet.String()

	manager.mu.Lock()
	defer manager.mu.Unlock()

	// Read current config
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		http.Error(w, "Failed to read config file", http.StatusInternalServerError)
		return
	}
	var currentConfig Config
	if err := yaml.Unmarshal(yamlFile, &currentConfig); err != nil {
		http.Error(w, "Failed to parse config file", http.StatusInternalServerError)
		return
	}

	// Add IP to all rules
	for i := range currentConfig.Forwards {
		found := false
		for _, allowedIP := range currentConfig.Forwards[i].AllowedIPs {
			if allowedIP == cidrStr {
				found = true
				break
			}
		}
		if !found {
			currentConfig.Forwards[i].AllowedIPs = append(currentConfig.Forwards[i].AllowedIPs, cidrStr)
		}
	}

	if err := reloadConfigAndForwarders(currentConfig); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Added %s to all allowed IP lists and reloaded configuration.", cidrStr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Successfully added %s to all rules.", cidrStr)))
}

func removeTempIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RemoveIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(req.IP)
	if ip == nil {
		http.Error(w, "Invalid IP address: "+req.IP, http.StatusBadRequest)
		return
	}

	// Remove from temporary IP pool
	if tempIPPool.Remove(req.IP) {
		log.Printf("Removed IP %s from temporary IP pool", req.IP)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Successfully removed %s from temporary whitelist", req.IP)))
	} else {
		http.Error(w, fmt.Sprintf("IP %s not found in temporary whitelist", req.IP), http.StatusNotFound)
	}
}

// reloadConfigAndForwarders stops, checks, saves, and starts the forwarders.
// The manager's mutex must be held by the caller.
func reloadConfigAndForwarders(newConfig Config) error {
	oldForwards := manager.currentForwards

	log.Println("Received config update, stopping current services to check ports...")
	manager.StopAll()

	if errs := checkPortsAvailability(newConfig.Forwards); len(errs) > 0 {
		log.Println("New config port check failed, rolling back to old config...")
		manager.StartForwarders(oldForwards) // Rollback
		var errMsgs []string
		for _, err := range errs {
			errMsgs = append(errMsgs, err.Error())
		}
		return fmt.Errorf("new config contains unavailable ports: %s", strings.Join(errMsgs, ", "))
	}

	log.Println("New config port check successful, applying...")
	yamlData, err := yaml.Marshal(&newConfig)
	if err != nil {
		log.Println("Rollback: Failed to marshal new config to YAML", err)
		manager.StartForwarders(oldForwards)
		return fmt.Errorf("failed to convert to YAML: %w", err)
	}

	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		log.Println("Rollback: Failed to write config file", err)
		manager.StartForwarders(oldForwards)
		return fmt.Errorf("failed to write config file: %w", err)
	}

	manager.StartForwarders(newConfig.Forwards)
	log.Println("Configuration successfully updated and reloaded.")
	return nil
}

func loginHandler(w http.ResponseWriter, r *http.Request, auth BasicAuth) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(loginHTML)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate credentials
	if loginReq.Username != auth.Username || loginReq.Password != auth.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create session
	sessionID := createSession()
	if sessionID == "" {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   24 * 60 * 60, // 24 hours
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session cookie
	cookie, err := r.Cookie("session_id")
	if err == nil {
		// Remove session from memory
		sessionsMux.Lock()
		delete(sessions, cookie.Value)
		sessionsMux.Unlock()
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logout successful"))
}

func startAdminServer(addr string, auth BasicAuth) {
	if addr == "" {
		log.Println("admin_addr not configured, web admin interface not started.")
		return
	}

	configHandlerWithAuth := requireAuth(configHandler, auth.Username, auth.Password)
	allowHandlerWithAuth := requireAuth(allowHandler, auth.Username, auth.Password)
	removeTempIPHandlerWithAuth := requireAuth(removeTempIPHandler, auth.Username, auth.Password)
	allowMyIPHandlerWithAuth := requireAuth(allowMyIPHandler, auth.Username, auth.Password)
	rootHandlerWithAuth := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	}, auth.Username, auth.Password)

	ipHandler := func(w http.ResponseWriter, r *http.Request) {
		ipStr := getClientIP(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ip": ipStr})
	}

	ipPoolHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ips := tempIPPool.GetAll()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ips":         ips,
			"maxSize":     tempIPPool.maxSize,
			"currentSize": len(ips),
		})
	}

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r, auth)
	})
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r, auth)
	})
	http.HandleFunc("/api/logout", logoutHandler)
	http.HandleFunc("/api/config", configHandlerWithAuth)
	http.HandleFunc("/api/allow", allowHandlerWithAuth)
	http.HandleFunc("/api/remove-temp-ip", removeTempIPHandlerWithAuth)
	http.HandleFunc("/api/allow-my-ip", allowMyIPHandlerWithAuth)
	http.HandleFunc("/api/ip", requireAuth(ipHandler, auth.Username, auth.Password))
	http.HandleFunc("/api/ip-pool", requireAuth(ipPoolHandler, auth.Username, auth.Password))

	// PWA files - served without authentication
	http.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(manifestJSON)
	})
	http.HandleFunc("/service-worker.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(serviceWorkerJS)
	})
	http.HandleFunc("/browserconfig.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(browserconfigXML)
	})
	http.HandleFunc("/shield-icon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(shieldIconSVG)
	})

	http.HandleFunc("/", rootHandlerWithAuth)

	log.Printf("Starting web admin interface, listening on http://%s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("Failed to start web admin interface: %v", err)
	}
}

// --- Main & Lifecycle ---

func main() {
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config.yml: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Failed to parse config.yml: %v", err)
	}

	// Initialize database
	if err := initDatabase(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Set default temp IP pool size if not configured
	if config.TempIPPoolSize <= 0 {
		config.TempIPPoolSize = 10
	}

	// Initialize temporary IP pool with configured size
	tempIPPool = NewTempIPPool(config.TempIPPoolSize, ipPoolPath)

	if errs := checkPortsAvailability(config.Forwards); len(errs) > 0 {
		for _, err := range errs {
			log.Println(err)
		}
		log.Fatalln("One or more ports are unavailable, exiting.")
	}

	// Set up graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go startAdminServer(config.AdminAddr, config.BasicAuth)

	manager.mu.Lock()
	manager.StartForwarders(config.Forwards)
	manager.mu.Unlock()

	log.Println("Service started. Press Ctrl+C to exit gracefully.")

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutdown signal received, performing graceful shutdown...")

	// Close database connection
	closeDatabase()

	// Save IP pool before exit
	tempIPPool.Shutdown()

	// Stop all forwarders
	manager.mu.Lock()
	manager.StopAll()
	manager.mu.Unlock()

	log.Println("Graceful shutdown completed.")
}

// --- Port Forwarding & Validation Logic ---

func isIPAllowed(remoteIP net.IP, allowedNets []*net.IPNet) bool {
	if len(allowedNets) == 0 {
		return true
	}

	// Check configured allowed networks
	for _, network := range allowedNets {
		if network.Contains(remoteIP) {
			return true
		}
	}

	// Check temporary IP pool
	if tempIPPool.Contains(remoteIP.String()) {
		// Update trigger time when IP is matched
		tempIPPool.UpdateTriggerTime(remoteIP.String())
		return true
	}

	return false
}

func checkPortsAvailability(forwards []Forward) []error {
	var unavailablePorts []error
	for _, f := range forwards {
		for _, proto := range f.Protocols {
			switch proto {
			case "tcp":
				ln, err := net.Listen("tcp", f.From)
				if err != nil {
					unavailablePorts = append(unavailablePorts, fmt.Errorf("TCP port %s is not available", f.From))
				} else {
					ln.Close()
				}
			case "udp":
				addr, err := net.ResolveUDPAddr("udp", f.From)
				if err != nil {
					unavailablePorts = append(unavailablePorts, fmt.Errorf("UDP address %s is invalid", f.From))
					continue
				}
				conn, err := net.ListenUDP("udp", addr)
				if err != nil {
					unavailablePorts = append(unavailablePorts, fmt.Errorf("UDP port %s is not available", f.From))
				} else {
					conn.Close()
				}
			}
		}
	}
	return unavailablePorts
}

func handleTCP(ctx context.Context, from, to string, allowedNets []*net.IPNet) {
	listener, err := net.Listen("tcp", from)
	if err != nil {
		log.Printf("Failed to listen on TCP %s: %v", from, err)
		return
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				log.Printf("Stopping TCP listener on %s", from)
				return
			}
			log.Printf("Failed to accept TCP connection: %v", err)
			continue
		}

		remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			conn.Close()
			continue
		}

		if !isIPAllowed(remoteAddr.IP, allowedNets) {
			log.Printf("Blocking TCP connection from %s (IP not in allowed list)", remoteAddr.IP)
			conn.Close()
			continue
		}

		go forwardTCP(ctx, conn, to)
	}
}

func forwardTCP(ctx context.Context, conn net.Conn, to string) {
	defer conn.Close()
	target, err := net.Dial("tcp", to)
	if err != nil {
		return
	}
	defer target.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
		target.Close()
	}()

	go io.Copy(target, conn)
	io.Copy(conn, target)
}

func handleUDP(ctx context.Context, from, to string, allowedNets []*net.IPNet) {
	fromAddr, err := net.ResolveUDPAddr("udp", from)
	if err != nil {
		log.Printf("Failed to resolve UDP address %s: %v", from, err)
		return
	}

	toAddr, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		log.Printf("Failed to resolve UDP address %s: %v", to, err)
		return
	}

	listener, err := net.ListenUDP("udp", fromAddr)
	if err != nil {
		log.Printf("Failed to listen on UDP %s: %v", from, err)
		return
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	sessions := make(map[string]*net.UDPConn)
	var mu sync.Mutex
	buf := make([]byte, 65535)

	for {
		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				log.Printf("Stopping UDP listener on %s", from)
				return
			}
			continue
		}

		if !isIPAllowed(clientAddr.IP, allowedNets) {
			continue
		}

		mu.Lock()
		targetConn, ok := sessions[clientAddr.String()]
		mu.Unlock()

		if !ok {
			targetConn, err = net.DialUDP("udp", nil, toAddr)
			if err != nil {
				continue
			}

			mu.Lock()
			sessions[clientAddr.String()] = targetConn
			mu.Unlock()

			go func(ctx context.Context, clientAddr *net.UDPAddr, targetConn *net.UDPConn) {
				defer func() {
					targetConn.Close()
					mu.Lock()
					delete(sessions, clientAddr.String())
					mu.Unlock()
				}()

				go func() {
					<-ctx.Done()
					targetConn.Close()
				}()

				buf := make([]byte, 65535)
				for {
					targetConn.SetReadDeadline(time.Now().Add(udpTimeout))
					n, err := targetConn.Read(buf)
					if err != nil {
						return
					}
					_, err = listener.WriteToUDP(buf[:n], clientAddr)
					if err != nil {
						return
					}
				}
			}(ctx, clientAddr, targetConn)
		}

		targetConn.Write(buf[:n])
	}
}
