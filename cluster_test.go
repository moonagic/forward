package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestMasterEdgeHeartbeatAndConfigSync tests the complete heartbeat lifecycle
// including node registration, IP pool syncing, and config push from Master to Edge.
func TestMasterEdgeHeartbeatAndConfigSync(t *testing.T) {
	// Initialize isolated Master TempIPPool
	masterPoolFile := "test_master_pool.json"
	defer os.Remove(masterPoolFile)
	tempIPPool = NewTempIPPool(10, masterPoolFile)
	defer tempIPPool.Shutdown()

	// Clear global node registry for clean test
	nodeRegistry = NewNodeRegistry()

	currentConfigMux.Lock()
	currentConfig = Config{
		Mode:      "master",
		NodeID:    "master-main",
		NodeToken: "cluster-secret-key",
	}
	currentConfigMux.Unlock()

	// 1. Test invalid token rejection
	badReqPayload := HeartbeatRequest{
		NodeID:    "edge-hk-01",
		NodeName:  "Hong Kong Edge",
		NodeToken: "wrong-token",
	}
	badBody, _ := json.Marshal(badReqPayload)
	req := httptest.NewRequest("POST", "/api/internal/heartbeat", bytes.NewReader(badBody))
	w := httptest.NewRecorder()
	internalHeartbeatHandler(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected HTTP 401 Unauthorized for bad token, got %d", w.Result().StatusCode)
	}

	// 2. Test valid heartbeat & Edge registration
	validReqPayload := HeartbeatRequest{
		NodeID:    "edge-hk-01",
		NodeName:  "Hong Kong Edge",
		NodeToken: "cluster-secret-key",
		Forwards: []Forward{
			{Protocols: []string{"tcp"}, From: "0.0.0.0:18080", To: "127.0.0.1:8080"},
		},
		NewIPs: []TempIPEntry{
			{IP: "1.1.1.1", LastTriggered: time.Now()},
		},
	}
	validBody, _ := json.Marshal(validReqPayload)
	req = httptest.NewRequest("POST", "/api/internal/heartbeat", bytes.NewReader(validBody))
	req.RemoteAddr = "192.168.1.100:54321"
	w = httptest.NewRecorder()
	internalHeartbeatHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP 200 OK for valid heartbeat, got %d", w.Result().StatusCode)
	}

	var hbResp HeartbeatResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&hbResp); err != nil {
		t.Fatalf("Failed to decode HeartbeatResponse: %v", err)
	}

	if hbResp.Status != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", hbResp.Status)
	}

	// Verify IP was synced to Master pool
	if !tempIPPool.Contains("1.1.1.1") {
		t.Errorf("Expected Master IP pool to contain '1.1.1.1'")
	}

	// Verify Node is in registry
	nodes := nodeRegistry.GetAll()
	if len(nodes) != 1 {
		t.Fatalf("Expected 1 registered edge node, got %d", len(nodes))
	}
	if nodes[0].NodeID != "edge-hk-01" || nodes[0].Status != "online" {
		t.Errorf("Unexpected node status in registry: %+v", nodes[0])
	}

	// 3. Test Master queuing a config update for Edge node
	desiredConfig := Config{
		Forwards: []Forward{
			{Protocols: []string{"tcp", "udp"}, From: "0.0.0.0:28080", To: "127.0.0.1:8080"},
		},
	}
	if ok := nodeRegistry.SetDesiredConfig("edge-hk-01", desiredConfig); !ok {
		t.Fatalf("Failed to queue config for edge-hk-01")
	}

	// Next heartbeat from Edge should receive desired config
	req = httptest.NewRequest("POST", "/api/internal/heartbeat", bytes.NewReader(validBody))
	w = httptest.NewRecorder()
	internalHeartbeatHandler(w, req)

	json.NewDecoder(w.Result().Body).Decode(&hbResp)
	if hbResp.DesiredConfig == nil {
		t.Fatalf("Expected DesiredConfig in heartbeat response, got nil")
	}
	if len(hbResp.DesiredConfig.Forwards) != 1 || hbResp.DesiredConfig.Forwards[0].From != "0.0.0.0:28080" {
		t.Errorf("Unexpected DesiredConfig content: %+v", hbResp.DesiredConfig)
	}
}

// TestEdgeAllowSyncingToMaster tests /api/allow on Edge node
// adding IP to local pool immediately and queueing it for Master sync.
func TestEdgeAllowSyncingToMaster(t *testing.T) {
	edgePoolFile := "test_edge_pool.json"
	defer os.Remove(edgePoolFile)
	tempIPPool = NewTempIPPool(10, edgePoolFile)
	defer tempIPPool.Shutdown()

	currentConfigMux.Lock()
	currentConfig = Config{
		Mode:      "edge",
		NodeID:    "edge-us-01",
		MasterURL: "http://127.0.0.1:9090",
	}
	currentConfigMux.Unlock()

	// Drain any leftover IPs in pendingSyncIPs
	pendingSyncIPs.Drain()

	req := httptest.NewRequest("POST", "/api/allow", nil)
	req.Header.Set("X-Real-IP", "203.0.113.88")
	w := httptest.NewRecorder()

	allowHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP 200 OK from /api/allow on Edge, got %d", w.Result().StatusCode)
	}

	// Verify local instant addition
	if !tempIPPool.Contains("203.0.113.88") {
		t.Errorf("Expected Edge local pool to contain '203.0.113.88' immediately")
	}

	// Verify IP was queued in pendingSyncIPs for Master heartbeat
	pending := pendingSyncIPs.Drain()
	if len(pending) != 1 || pending[0].IP != "203.0.113.88" {
		t.Errorf("Expected pending sync buffer to contain '203.0.113.88', got %+v", pending)
	}
}

// TestEdgeWebAccessRestriction tests that Edge nodes disable the Web UI
// and redirect/block browser access to index.html and login.html.
func TestEdgeWebAccessRestriction(t *testing.T) {
	currentConfigMux.Lock()
	currentConfig = Config{
		Mode:      "edge",
		MasterURL: "https://master.example.com:9090",
	}
	currentConfigMux.Unlock()

	// Access / directly on Edge
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	if !isWebUIDisabledOnEdge(w, req) {
		t.Errorf("Expected isWebUIDisabledOnEdge to return true for Edge node")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected HTTP 302 Redirect to Master URL, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "https://master.example.com:9090" {
		t.Errorf("Expected Location header 'https://master.example.com:9090', got '%s'", resp.Header.Get("Location"))
	}
}

// TestGetNodesEndpoint tests Master node listing API (/api/nodes).
func TestGetNodesEndpoint(t *testing.T) {
	nodeRegistry = NewNodeRegistry()
	nodeRegistry.RegisterOrUpdate("edge-1", "Edge Node 1", "10.0.0.5", nil)

	currentConfigMux.Lock()
	currentConfig = Config{
		Mode:     "master",
		NodeID:   "master-node",
		NodeName: "Primary Master",
	}
	currentConfigMux.Unlock()

	req := httptest.NewRequest("GET", "/api/nodes", nil)
	w := httptest.NewRecorder()

	nodesHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP 200 OK from /api/nodes, got %d", w.Result().StatusCode)
	}

	var data struct {
		Nodes []RegisteredNode `json:"nodes"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&data); err != nil {
		t.Fatalf("Failed to decode /api/nodes response: %v", err)
	}

	if len(data.Nodes) != 2 {
		t.Fatalf("Expected 2 nodes (Master + 1 Edge), got %d", len(data.Nodes))
	}

	// Verify Master is first entry
	if data.Nodes[0].NodeID != "master-node" || data.Nodes[0].NodeName != "Primary Master" {
		t.Errorf("Unexpected Master node info in /api/nodes: %+v", data.Nodes[0])
	}
	// Verify Edge is second entry
	if data.Nodes[1].NodeID != "edge-1" {
		t.Errorf("Unexpected Edge node info in /api/nodes: %+v", data.Nodes[1])
	}
}

// TestHTTPSAndTLSSkipVerify tests Edge node communicating with Master over HTTPS
// when tls_skip_verify is enabled.
func TestHTTPSAndTLSSkipVerify(t *testing.T) {
	// Create HTTPS test server with self-signed certificate on Master
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/internal/heartbeat" {
			resp := HeartbeatResponse{
				Status:       "ok",
				MasterIPPool: []TempIPEntry{{IP: "8.8.8.8", LastTriggered: time.Now()}},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})

	ts := httptest.NewTLSServer(handler)
	defer ts.Close()

	testPoolFile := "test_tls_pool.json"
	defer os.Remove(testPoolFile)
	tempIPPool = NewTempIPPool(10, testPoolFile)
	defer tempIPPool.Shutdown()

	currentConfigMux.Lock()
	currentConfig = Config{
		Mode:          "edge",
		NodeID:        "edge-tls",
		MasterURL:     ts.URL,
		TLSSkipVerify: true,
	}
	currentConfigMux.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch Edge heartbeat worker
	startEdgeHeartbeatWorker(ctx, currentConfig)

	// Wait for heartbeat to run and sync Master's IP pool
	deadline := time.Now().Add(2 * time.Second)
	synced := false
	for time.Now().Before(deadline) {
		if tempIPPool.Contains("8.8.8.8") {
			synced = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !synced {
		t.Errorf("Edge heartbeat failed to sync IP '8.8.8.8' over HTTPS with TLSSkipVerify")
	}
}

// TestTCPForwardingIPAllowedCheck verifies TCP forwarding performs fast O(1)
// RAM checks against TempIPPool and static CIDRs without blocking on network calls.
func TestTCPForwardingIPAllowedCheck(t *testing.T) {
	poolFile := "test_tcp_pool.json"
	defer os.Remove(poolFile)
	tempIPPool = NewTempIPPool(10, poolFile)
	defer tempIPPool.Shutdown()

	// Parse static CIDR
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	allowedNets := []*net.IPNet{network}

	// 1. IP in static whitelist
	if !isIPAllowed(net.ParseIP("192.168.1.50"), allowedNets) {
		t.Errorf("Expected 192.168.1.50 to be allowed by CIDR whitelist")
	}

	// 2. IP NOT in static whitelist and NOT in temp pool
	if isIPAllowed(net.ParseIP("10.0.0.1"), allowedNets) {
		t.Errorf("Expected 10.0.0.1 to be blocked")
	}

	// 3. Add IP to TempIPPool and verify it becomes allowed immediately
	tempIPPool.Add("10.0.0.1")
	if !isIPAllowed(net.ParseIP("10.0.0.1"), allowedNets) {
		t.Errorf("Expected 10.0.0.1 to be allowed after adding to TempIPPool")
	}
}
