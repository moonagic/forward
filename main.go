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

// --- Global Manager ---

var manager = NewForwarderManager()

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

	oldForwards := manager.currentForwards

	log.Println("Received config update request, stopping current services to check ports...")
	manager.StopAll()

	if errs := checkPortsAvailability(newConfig.Forwards); len(errs) > 0 {
		log.Println("New config port check failed, rolling back to old config...")
		manager.StartForwarders(oldForwards) // Rollback
		var errMsgs []string
		for _, err := range errs {
			errMsgs = append(errMsgs, err.Error())
		}
		http.Error(w, "New config contains unavailable ports: "+strings.Join(errMsgs, ", "), http.StatusBadRequest)
		return
	}

	log.Println("New config port check successful, applying...")
	yamlData, err := yaml.Marshal(&newConfig)
	if err != nil {
		log.Println("Rollback: Failed to marshal new config to YAML", err)
		manager.StartForwarders(oldForwards)
		http.Error(w, "Failed to convert to YAML: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		log.Println("Rollback: Failed to write config file", err)
		manager.StartForwarders(oldForwards)
		http.Error(w, "Failed to write config file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	manager.StartForwarders(newConfig.Forwards)
	log.Println("Configuration successfully updated and reloaded.")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Config saved and reloaded successfully."))
}

func startAdminServer(addr string, auth BasicAuth) {
	if addr == "" {
		log.Println("admin_addr not configured, web admin interface not started.")
		return
	}

	configHandlerWithAuth := basicAuth(configHandler, auth.Username, auth.Password)
	rootHandlerWithAuth := basicAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	}, auth.Username, auth.Password)

	http.HandleFunc("/api/config", configHandlerWithAuth)
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
	for _, network := range allowedNets {
		if network.Contains(remoteIP) {
			return true
		}
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
