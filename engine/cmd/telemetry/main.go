package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	fileMu  sync.Mutex
	logFile string
)

type TelemetryEntry struct {
	Timestamp string    `json:"timestamp"`
	Features  []float64 `json:"features"`
	Verdict   int       `json:"verdict"`
	Consensus float64   `json:"consensus"`
	Reason    string    `json:"reason"`
	IP        string    `json:"ip"`
}

func main() {
	logFile = "/mnt/data/databases/telemetry.jsonl"
	os.MkdirAll("/mnt/data/databases", 0755)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	})
	http.HandleFunc("/api/telemetry", handleTelemetry)

	log.Println("[telemetry] Receiver on :9002")
	http.ListenAndServe(":9002", nil)
}

func handleTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var e TelemetryEntry
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		w.WriteHeader(400)
		return
	}
	e.Timestamp = time.Now().UTC().Format(time.RFC3339)

	fileMu.Lock()
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		json.NewEncoder(f).Encode(e)
		f.Close()
	}
	fileMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok"}`)
}
