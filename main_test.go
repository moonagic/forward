package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNodeRegistry(t *testing.T) {
	registry := NewNodeRegistry()

	forwards := []Forward{
		{
			Protocols:  []string{"tcp"},
			From:       "0.0.0.0:18080",
			To:         "127.0.0.1:8080",
			AllowedIPs: []string{"192.168.1.0/24"},
		},
	}

	node, desired := registry.RegisterOrUpdate("edge-1", "Edge Node 1", "192.168.1.50", forwards)
	if node.NodeID != "edge-1" {
		t.Errorf("Expected node_id 'edge-1', got '%s'", node.NodeID)
	}
	if node.Status != "online" {
		t.Errorf("Expected status 'online', got '%s'", node.Status)
	}
	if desired != nil {
		t.Errorf("Expected desired config to be nil initially, got %+v", desired)
	}

	allNodes := registry.GetAll()
	if len(allNodes) != 1 {
		t.Fatalf("Expected 1 registered node, got %d", len(allNodes))
	}
	if allNodes[0].NodeName != "Edge Node 1" {
		t.Errorf("Expected node name 'Edge Node 1', got '%s'", allNodes[0].NodeName)
	}

	// Test setting desired config
	newConfig := Config{
		Forwards: []Forward{
			{Protocols: []string{"tcp", "udp"}, From: "0.0.0.0:9000", To: "1.1.1.1:9000"},
		},
	}
	ok := registry.SetDesiredConfig("edge-1", newConfig)
	if !ok {
		t.Errorf("Failed to set desired config for edge-1")
	}

	// Next heartbeat should retrieve the desired config
	_, desired = registry.RegisterOrUpdate("edge-1", "Edge Node 1", "192.168.1.50", forwards)
	if desired == nil {
		t.Fatalf("Expected desired config on heartbeat, got nil")
	}
	if len(desired.Forwards) != 1 || desired.Forwards[0].From != "0.0.0.0:9000" {
		t.Errorf("Unexpected desired config content: %+v", desired)
	}

	// Second heartbeat after retrieval should return nil
	_, desired = registry.RegisterOrUpdate("edge-1", "Edge Node 1", "192.168.1.50", forwards)
	if desired != nil {
		t.Errorf("Expected desired config to be cleared after delivery, got %+v", desired)
	}
}

func TestPendingIPBuffer(t *testing.T) {
	buf := &PendingIPBuffer{}
	if len(buf.Drain()) != 0 {
		t.Errorf("Expected empty buffer initially")
	}

	now := time.Now()
	buf.Add("10.0.0.1", now)
	buf.Add("10.0.0.2", now)

	drained := buf.Drain()
	if len(drained) != 2 {
		t.Fatalf("Expected 2 drained IPs, got %d", len(drained))
	}
	if drained[0].IP != "10.0.0.1" || drained[1].IP != "10.0.0.2" {
		t.Errorf("Unexpected drained IP contents: %+v", drained)
	}

	if len(buf.Drain()) != 0 {
		t.Errorf("Expected buffer to be empty after draining")
	}
}

func TestInternalHeartbeatHandler(t *testing.T) {
	tempIPPool = NewTempIPPool(10, "test_ip_pool.json")
	defer tempIPPool.Shutdown()

	reqPayload := HeartbeatRequest{
		NodeID:    "edge-test",
		NodeName:  "Test Edge",
		NodeToken: "",
		Forwards:  []Forward{},
		NewIPs: []TempIPEntry{
			{IP: "203.0.113.5", LastTriggered: time.Now()},
		},
	}

	bodyBytes, _ := json.Marshal(reqPayload)
	req := httptest.NewRequest("POST", "/api/internal/heartbeat", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	internalHeartbeatHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP 200 OK, got %d", resp.StatusCode)
	}

	var hbResp HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hbResp); err != nil {
		t.Fatalf("Failed to decode HeartbeatResponse: %v", err)
	}

	if hbResp.Status != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", hbResp.Status)
	}

	if !tempIPPool.Contains("203.0.113.5") {
		t.Errorf("Expected Master TempIPPool to contain IP sent by Edge")
	}
}
