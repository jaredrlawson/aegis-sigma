package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/clusterer"
	"github.com/aegis-sigma/engine/pkg/triadclient"
)

const (
	ClusterInterval = 60 * time.Second
	ClusterLookback = 168 * time.Hour // 7 days
)

func main() {
	config.RequireTelemetry()
	// Start the clustering loop in the background — this is the real Soul work.
	go clusterer.StartLoop(ClusterInterval, ClusterLookback)
	log.Printf("[SOUL] clustering loop started: interval=%s lookback=%s", ClusterInterval, ClusterLookback)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		llmEnabled := false
		if key := os.Getenv("OPENAI_API_KEY"); key != "" {
			llmEnabled = true
		} else if data, err := os.ReadFile(config.VaultKeyPath); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			llmEnabled = true
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok", "agent": "soul-go", "version": "2.0.0",
			"llm_enabled": llmEnabled,
			"clustering":  "active",
		})
	})
	http.HandleFunc("/security/check", handleSecurityCheck)
	http.HandleFunc("/forensics/summary", handleForensicsSummary)
	http.HandleFunc("/forensics/fbi-manifest", handleFBImanifest)
	http.HandleFunc("/forensic-attribution", handleForensicAttribution)
	http.HandleFunc("/cluster/run", handleClusterRun)

	fmt.Printf("[SOUL] Go soul on :%d (clustering every %s)\n", config.SoulPort, ClusterInterval)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", config.SoulPort), nil); err != nil {
		log.Fatalf("[SOUL] listen error: %v", err)
	}
}

// handleSecurityCheck runs the shield rules + LLM, and on a hostile verdict
// dispatches the Soul analysis so its result is persisted against the cluster
// rather than discarded.
func handleSecurityCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var params map[string]interface{}
	json.NewDecoder(r.Body).Decode(&params)

	result := triadclient.ShieldCheck(params)
	ip, _ := params["ip"].(string)

	if verdict, ok := result["verdict"].(string); ok && verdict == "block" && ip != "" {
		analysis := triadclient.SoulEngine(fmt.Sprintf(
			"Analyze this attack: IP=%s UA=%s Path=%s Method=%v",
			ip, params["ua"], params["path"], params["method"]))
		// Persist the Soul analysis back to the result so callers can see it.
		if assessment, ok := analysis["assessment"].(string); ok {
			result["soul_assessment"] = assessment
		}
		if conf, ok := analysis["confidence"].(float64); ok {
			result["soul_confidence"] = conf
		}
		if at, ok := analysis["attacker_type"].(string); ok {
			result["attacker_type"] = at
		}
		if rec, ok := analysis["recommendation"].(string); ok {
			result["recommendation"] = rec
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleForensicsSummary now returns real counts from brain.sqlite.
func handleForensicsSummary(w http.ResponseWriter, r *http.Request) {
	secEvents, forensicReports, err := clusterer.ForensicsSummary()
	if err != nil {
		jsonOut(w, map[string]interface{}{
			"security_events": 0, "forensic_reports": 0, "error": err.Error(),
		})
		return
	}
	jsonOut(w, map[string]int{
		"security_events":  secEvents,
		"forensic_reports": forensicReports,
	})
}

// handleFBImanifest returns the real FBI evidence breakdown by event type.
func handleFBImanifest(w http.ResponseWriter, r *http.Request) {
	total, byType, err := clusterer.FBIEvidenceManifest()
	if err != nil {
		jsonOut(w, map[string]interface{}{"total": 0, "by_type": map[string]int{}, "error": err.Error()})
		return
	}
	jsonOut(w, map[string]interface{}{
		"total":   total,
		"by_type": byType,
	})
}

// handleForensicAttribution returns the live clustering result for the
// dashboard's Entity Attribution panel. attribution.js consumes this.
func handleForensicAttribution(w http.ResponseWriter, r *http.Request) {
	result, err := clusterer.GetAttribution(ClusterLookback)
	if err != nil {
		jsonOut(w, map[string]interface{}{
			"masterActor":     nil,
			"lieutenants":     []interface{}{},
			"tools":           []interface{}{},
			"scans":           []interface{}{},
			"all":             []interface{}{},
			"totalClusters":   0,
			"totalAttacks":    0,
			"error":           err.Error(),
		})
		return
	}
	jsonOut(w, result)
}

// handleClusterRun triggers a manual clustering pass on demand.
func handleClusterRun(w http.ResponseWriter, r *http.Request) {
	result, err := clusterer.RunClustering(ClusterLookback)
	if err != nil {
		jsonOut(w, map[string]interface{}{"success": false, "error": err.Error()}, 500)
		return
	}
	jsonOut(w, map[string]interface{}{
		"success":       true,
		"totalClusters": result.TotalClusters,
		"totalAttacks":  result.TotalAttacks,
	})
}

func jsonOut(w http.ResponseWriter, data interface{}, status ...int) {
	code := 200
	if len(status) > 0 {
		code = status[0]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}
