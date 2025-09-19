package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed index.html
var indexHTML []byte

const udpTimeout = 5 * time.Minute
const configPath = "config.yml"

// --- Data Structures ---

type BasicAuth struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type Config struct {
	AdminAddr string    `yaml:"admin_addr" json:"admin_addr"`
	BasicAuth BasicAuth `yaml:"basic_auth" json:"basic_auth"`
	Forwards  []Forward `yaml:"forwards" json:"forwards"`
}

type Forward struct {
	Protocols  []string `yaml:"protocols" json:"protocols"`
	From       string   `yaml:"from" json:"from"`
	To         string   `yaml:"to" json:"to"`
	AllowedIPs []string `yaml:"allowed_ips" json:"allowed_ips"`
}

// TempIPPool manages a pool of temporarily allowed IPs with FIFO eviction
type TempIPPool struct {
	mu      sync.RWMutex
	ips     []string    // FIFO queue of IPs
	ipMap   map[string]bool // Fast lookup
	maxSize int
}

type RemoveIPRequest struct {
	IP string `json:"ip"`
}

// --- Global Manager ---

var manager = NewForwarderManager()
var tempIPPool = NewTempIPPool(10)

// --- Temporary IP Pool ---

func NewTempIPPool(maxSize int) *TempIPPool {
	return &TempIPPool{
		ips:     make([]string, 0, maxSize),
		ipMap:   make(map[string]bool),
		maxSize: maxSize,
	}
}

func (pool *TempIPPool) Add(ip string) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// If IP already exists, move it to the end (most recent)
	if pool.ipMap[ip] {
		// Find and remove the existing IP
		for i, existingIP := range pool.ips {
			if existingIP == ip {
				pool.ips = append(pool.ips[:i], pool.ips[i+1:]...)
				break
			}
		}
		// Add it to the end
		pool.ips = append(pool.ips, ip)
		return false // IP already existed, just moved to top
	}

	// If we're at capacity, remove the oldest IP
	if len(pool.ips) >= pool.maxSize {
		oldestIP := pool.ips[0]
		pool.ips = pool.ips[1:]
		delete(pool.ipMap, oldestIP)
	}

	// Add the new IP
	pool.ips = append(pool.ips, ip)
	pool.ipMap[ip] = true
	return true // New IP added
}

func (pool *TempIPPool) Contains(ip string) bool {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.ipMap[ip]
}

func (pool *TempIPPool) GetAll() []string {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	result := make([]string, len(pool.ips))
	copy(result, pool.ips)
	return result
}

func (pool *TempIPPool) Remove(ip string) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Check if IP exists
	if !pool.ipMap[ip] {
		return false
	}

	// Find and remove the IP from slice
	for i, existingIP := range pool.ips {
		if existingIP == ip {
			pool.ips = append(pool.ips[:i], pool.ips[i+1:]...)
			break
		}
	}

	// Remove from map
	delete(pool.ipMap, ip)
	return true
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

func basicAuth(handler http.HandlerFunc, username, password string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username == "" || password == "" {
			handler(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		handler(w, r)
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

func startAdminServer(addr string, auth BasicAuth) {
	if addr == "" {
		log.Println("admin_addr not configured, web admin interface not started.")
		return
	}

	configHandlerWithAuth := basicAuth(configHandler, auth.Username, auth.Password)
	allowHandlerWithAuth := basicAuth(allowHandler, auth.Username, auth.Password)
	removeTempIPHandlerWithAuth := basicAuth(removeTempIPHandler, auth.Username, auth.Password)
	allowMyIPHandlerWithAuth := basicAuth(allowMyIPHandler, auth.Username, auth.Password)
	rootHandlerWithAuth := basicAuth(func(w http.ResponseWriter, r *http.Request) {
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
			"ips": ips,
			"maxSize": tempIPPool.maxSize,
			"currentSize": len(ips),
		})
	}

	http.HandleFunc("/api/config", configHandlerWithAuth)
	http.HandleFunc("/api/allow", allowHandlerWithAuth)
	http.HandleFunc("/api/remove-temp-ip", removeTempIPHandlerWithAuth)
	http.HandleFunc("/api/allow-my-ip", allowMyIPHandlerWithAuth)
	http.HandleFunc("/api/ip", basicAuth(ipHandler, auth.Username, auth.Password))
	http.HandleFunc("/api/ip-pool", basicAuth(ipPoolHandler, auth.Username, auth.Password))
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

	if errs := checkPortsAvailability(config.Forwards); len(errs) > 0 {
		for _, err := range errs {
			log.Println(err)
		}
		log.Fatalln("One or more ports are unavailable, exiting.")
	}

	go startAdminServer(config.AdminAddr, config.BasicAuth)

	manager.mu.Lock()
	manager.StartForwarders(config.Forwards)
	manager.mu.Unlock()

	select {}
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
