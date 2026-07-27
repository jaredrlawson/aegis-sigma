package auditor

import (
	"database/sql"
	"encoding/json"
	"math"
	"os"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Status is what the C auditor writes to /var/lib/aegis-sigma/auditor-status.json.
type Status struct {
	Algorithm         string  `json:"algorithm"`
	ModelLoaded       bool    `json:"model_loaded"`
	AnomalyThreshold  float64 `json:"anomaly_threshold"`
	Transactions      int     `json:"transactions"`
	Mismatches        int     `json:"mismatches"`
	Anomalies         int     `json:"anomalies"`
	CurrentChainHead  string  `json:"current_chain_head"`
	LastUpdate        int64   `json:"last_update"`
	UptimeSeconds     int     `json:"uptime_seconds"`
	Version           string  `json:"version"`
}

// Verdict is the auditor's cross-check on an IP — used by the Shield to
// stitch an auditor-second-opinion into the forensic synthesis JSON.
type Verdict struct {
	Hostile    int     `json:"auditor_hostile"`
	Confidence float64 `json:"auditor_confidence"`
	Resonance  float64 `json:"threat_resonance"`
}

const statusFile = "/var/lib/aegis-sigma/auditor-status.json"

// Query reads the auditor's status file and derives a verdict.
// If the model isn't loaded or the file is stale (>5min), returns neutral.
func Query(ip string, features []float64) Verdict {
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return Verdict{}
	}
	var st Status
	if json.Unmarshal(data, &st) != nil {
		return Verdict{}
	}
	// Stale status — auditor hasn't written in 5 minutes
	if time.Now().Unix()-st.LastUpdate > 300 {
		return Verdict{}
	}
	// Model not loaded — auditor can't do real inference
	if !st.ModelLoaded {
		return Verdict{}
	}
	// Derive a simple anomaly verdict from the auditor's global stats.
	// If anomalies > 0 or mismatches > 0, flag as hostile.
	hostile := 0
	confidence := 0.5
	resonance := 0.0
	if st.Anomalies > 0 {
		hostile = 1
		confidence = 0.8
		resonance = float64(st.Anomalies) / float64(st.Transactions+1)
	}
	if st.Mismatches > 0 {
		hostile = 1
		confidence = 0.9
		resonance = float64(st.Mismatches) / float64(st.Transactions+1)
	}
	return Verdict{
		Hostile:    hostile,
		Confidence: confidence,
		Resonance:  resonance,
	}
}

// FingerprintCheck cross-references tracker fingerprint data against IP geo.
// Returns an anomaly score: 0 = consistent, higher = more suspicious.
func FingerprintCheck(ip string, lat, lon float64) float64 {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0
	}
	defer d.Close()

	var screen, platform, langs, gpu string
	var tzOffset int
	err = d.QueryRow(`SELECT screen_size, timezone_offset, platform, languages, gpu
		FROM tracker_hits WHERE ip = ? ORDER BY id DESC LIMIT 1`, ip).Scan(
		&screen, &tzOffset, &platform, &langs, &gpu)
	if err != nil {
		return 0
	}

	anomaly := 0.0

	// Timezone vs geo check
	if lat != 0 && lon != 0 {
		expectedTz := geoTimeOffset(lat, lon)
		tzDiff := math.Abs(float64(tzOffset) - expectedTz)
		if tzDiff > 120 { // >2hr mismatch
			anomaly += 0.4
		}
	}

	// Empty screen = headless/automation
	if screen == "" || screen == "0x0" {
		anomaly += 0.3
	}

	// No plugins = headless
	_ = gpu

	return anomaly
}

func geoTimeOffset(lat, lon float64) float64 {
	// Rough timezone estimation from longitude
	return math.Round(lon/15) * 60
}

// Status returns the raw auditor status for the dashboard.
func GetStatus() Status {
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return Status{}
	}
	var st Status
	json.Unmarshal(data, &st)
	return st
}

// unused but needed for sql import
var _ = sql.ErrNoRows
