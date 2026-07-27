package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	StatusFile  = "/var/lib/aegis-sigma/auditor-status.json"
	AlertsFile  = "/var/log/aegis/auditor-alerts.log"
	BrainDB     = "/mnt/data/databases/brain.sqlite"
	LiveFile    = "/var/log/aegis/live_events.jsonl"
	GammaStats  = "/var/lib/aegis-sigma/models/gamma_stats.json"
	ShieldJSON  = "/var/lib/aegis-sigma/models/shield.json"
	SoulJSON    = "/var/lib/aegis-sigma/models/soul.json"
	ShieldConf  = "/etc/aegis-sigma/shield.conf"
	Port        = 20130
	Threshold   = 0.618
	WeightAlpha = 0.55
	WeightBeta  = 0.34
	WeightGamma = 0.11
	PHI         = 1.618033988749895
	ReplayCount = 1000
)

type State struct {
	PreviousHash    string  `json:"previous_hash"`
	CurrentHash     string  `json:"current_hash"`
	Transactions    int64   `json:"transaction_count"`
	Mismatches      int64   `json:"mismatch_count"`
	Anomalies       int64   `json:"anomaly_count"`
	ChainBreaks     int64   `json:"chain_break_count"`
	DriftDetected   bool    `json:"drift_detected"`
	IntegrityOK     bool    `json:"integrity_ok"`
	DriftZScore     float64 `json:"drift_z_score"`
	LastProcessedID int64   `json:"-"`
	LastRetrain     int64   `json:"-"`
	CycleCount      int64   `json:"-"`
	GammaWeights    []float64
	ModelHashes     map[string]string
	Services   ServiceHealth
	StartTime       time.Time
}

type ServiceHealth struct {
	CEngine   bool `json:"aegis_c"`
	Shield    bool `json:"aegis_shield"`
	Soul      bool `json:"aegis_soul"`
	Auditor   bool `json:"aegis_auditor"`
	Bridge    bool `json:"aegis_bridge"`
}

type ModelIntegrity struct {
	ShieldHash  string `json:"shield_hash"`
	SoulHash    string `json:"soul_hash"`
	GammaHash   string `json:"gamma_hash"`
	ShieldOK    bool   `json:"shield_ok"`
	SoulOK      bool   `json:"soul_ok"`
	GammaOK     bool   `json:"gamma_ok"`
}

type AuditSummary struct {
	Status            string          `json:"status"`
	Transactions      int64           `json:"transactions"`
	Anomalies         int64           `json:"anomalies"`
	Mismatches        int64           `json:"mismatches"`
	ChainBreaks       int64           `json:"chain_breaks"`
	DriftDetected     bool            `json:"drift_detected"`
	DriftZScore       float64         `json:"drift_z_score"`
	IntegrityOK       bool            `json:"integrity_ok"`
	ModelIntegrity    ModelIntegrity  `json:"model_integrity"`
	ServiceHealth     ServiceHealth   `json:"services"`
	ChainHead         string          `json:"chain_head"`
	LastUpdate        string          `json:"last_update"`
	UptimeSeconds     int64           `json:"uptime_seconds"`
	Version           string          `json:"version"`
	GammaWeights      GammaWeights    `json:"gamma_weights"`
}

type GammaWeights struct {
	Alpha float64 `json:"alpha"`
	Beta  float64 `json:"beta"`
	Gamma float64 `json:"gamma"`
	Phi   float64 `json:"phi_threshold"`
}

func main() {
	log.SetPrefix("[AUDITOR-GO] ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	state := &State{
		ModelHashes:   make(map[string]string),
		Services: ServiceHealth{},
		GammaWeights:  []float64{0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5},
		StartTime:     time.Now(),
	}

	loadGammaWeights(state)
	snapshotModelHashes(state)

	go runMainLoop(state)
	go serveHTTP(state)

	log.Printf("Auditor Go v2.0.0 on :%d | threshold=%.3f | weights: alpha=%.2f beta=%.2f gamma=%.2f",
		Port, Threshold, WeightAlpha, WeightBeta, WeightGamma)

	select {}
}

func runMainLoop(state *State) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		state.CycleCount++
		processNewEvents(state)
		checkServiceHealth(state)
		verifyModelIntegrity(state)
		verifyConfigIntegrity(state)
		detectDrift(state)
		if state.CycleCount%50 == 0 {
			retrainGamma(state)
		}
		writeStatus(state)
	}
}

func processNewEvents(state *State) {
	d, err := sql.Open("sqlite", BrainDB+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return
	}
	defer d.Close()

	rows, err := d.Query(`SELECT id, ip, COALESCE(tcp_ttl,128), COALESCE(tcp_window,65535),
		COALESCE(tcp_mss,1460), COALESCE(evidence,''), COALESCE(severity,'low'),
		COALESCE(score,0), COALESCE(features,'')
		FROM security_events
		WHERE id > ? AND tcp_ttl > 0
		ORDER BY id ASC LIMIT 500`, state.LastProcessedID)
	if err != nil {
		return
	}
	defer rows.Close()

	chainHead := state.CurrentHash
	anomalies := int64(0)
	mismatches := int64(0)
	chainBreaks := int64(0)
	scanned := int64(0)

	for rows.Next() {
		var id int64
		var ip, evidence, severity, featuresStr string
		var ttl, window, mss int
		var engineScore float64
		if err := rows.Scan(&id, &ip, &ttl, &window, &mss, &evidence, &severity, &engineScore, &featuresStr); err != nil {
			continue
		}
		scanned++
		state.LastProcessedID = id

		payload := fmt.Sprintf("%s|%d|%d|%d|%s", ip, ttl, window, mss, evidence)
		expectedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(chainHead+payload)))

		if chainHead != "" && state.Transactions > 0 {
			if !strings.HasPrefix(expectedHash, chainHead[:min(8, len(chainHead))]) {
				chainBreaks++
				alert(fmt.Sprintf("CHAIN_BREAK id=%d expected=%s", id, expectedHash[:16]))
			}
		}

		alpha := parseEvidence(evidence, "alpha")
		beta := parseEvidence(evidence, "beta")

		gammaScore := computeGammaScore(state, featuresStr, ttl, window, mss, severity)
		consensus := alpha*WeightAlpha + beta*WeightBeta + gammaScore*WeightGamma

		if consensus >= Threshold && engineScore < Threshold {
			mismatches++
			alert(fmt.Sprintf("MISMATCH id=%d ip=%s engine=%.4f consensus=%.4f", id, ip, engineScore, consensus))
		}
		if consensus >= Threshold {
			anomalies++
		}

		chainHead = expectedHash
	}

	state.CurrentHash = chainHead
	state.Transactions += scanned
	state.Anomalies += anomalies
	state.Mismatches += mismatches
	state.ChainBreaks += chainBreaks
}

func computeGammaScore(s *State, featuresStr string, ttl, window, mss int, severity string) float64 {
	features := parseFeatureString(featuresStr)
	if len(features) < 8 {
		features = []float64{
			float64(ttl) / 255.0,
			float64(window) / 65535.0,
			float64(mss) / 1500.0,
			0.5, 0.5, 0.5, 0.5,
			float64(severityToNum(severity)) / 4.0,
		}
	}

	score := 0.0
	for i := 0; i < len(features) && i < len(s.GammaWeights); i++ {
		score += features[i] * s.GammaWeights[i]
	}
	if len(s.GammaWeights) > 0 {
		score /= float64(len(s.GammaWeights))
	}
	return math.Min(math.Max(score, 0), 1.0)
}

func loadGammaWeights(s *State) {
	data, err := os.ReadFile(GammaStats)
	if err != nil {
		return
	}
	var stats struct {
		Weights []float64 `json:"weights"`
	}
	if json.Unmarshal(data, &stats) == nil && len(stats.Weights) > 0 {
		s.GammaWeights = stats.Weights
		log.Printf("Loaded gamma weights: %v", stats.Weights)
	}
}

func snapshotModelHashes(s *State) {
	s.ModelHashes["shield"] = fileHash(ShieldJSON)
	s.ModelHashes["soul"] = fileHash(SoulJSON)
	s.ModelHashes["gamma"] = fileHash(GammaStats)
	s.ModelHashes["conf"] = fileHash(ShieldConf)
	log.Printf("Model snapshot: shield=%s soul=%s gamma=%s",
		trunc(s.ModelHashes["shield"]), trunc(s.ModelHashes["soul"]), trunc(s.ModelHashes["gamma"]))
}

func fileHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func trunc(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func checkServiceHealth(s *State) {
	s.Services = ServiceHealth{
		CEngine: httpCheck("http://127.0.0.1:8086/", 2*time.Second),
		Shield:  httpCheck("http://127.0.0.1:3000/health", 2*time.Second),
		Soul:    httpCheck("http://127.0.0.1:3007/health", 2*time.Second),
		Auditor: true,
		Bridge:  httpCheck("http://127.0.0.1:8899/health", 2*time.Second),
	}
}

func httpCheck(url string, timeout time.Duration) bool {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func verifyModelIntegrity(s *State) {
	current := map[string]string{
		"shield": fileHash(ShieldJSON),
		"soul":   fileHash(SoulJSON),
		"gamma":  fileHash(GammaStats),
	}
	s.IntegrityOK = true
	for name, hash := range current {
		if hash == "" {
			continue
		}
		if s.ModelHashes[name] != "" && s.ModelHashes[name] != hash {
			s.IntegrityOK = false
			alert(fmt.Sprintf("MODEL_TAMPER detected=%s expected=%s current=%s",
				name, s.ModelHashes[name][:16], hash[:16]))
		}
	}
	s.ModelHashes["shield"] = current["shield"]
	s.ModelHashes["soul"] = current["soul"]
	s.ModelHashes["gamma"] = current["gamma"]
}

func verifyConfigIntegrity(s *State) {
	current := fileHash(ShieldConf)
	if current == "" {
		return
	}
	if s.ModelHashes["conf"] != "" && s.ModelHashes["conf"] != current {
		s.IntegrityOK = false
		alert(fmt.Sprintf("CONFIG_TAMPER expected=%s current=%s",
			s.ModelHashes["conf"][:16], current[:16]))
	}
	s.ModelHashes["conf"] = current
}

func detectDrift(s *State) {
	d, err := sql.Open("sqlite", BrainDB+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return
	}
	defer d.Close()

	statsData, err := os.ReadFile(GammaStats)
	if err != nil {
		return
	}
	var gammaStats struct {
		Stats []struct {
			FeatureIdx int     `json:"feature_idx"`
			Mean       float64 `json:"mean"`
			M2         float64 `json:"M2"`
			Count      int     `json:"count"`
		} `json:"stats"`
	}
	if json.Unmarshal(statsData, &gammaStats) != nil || len(gammaStats.Stats) == 0 {
		return
	}

	rows, err := d.Query(`SELECT COALESCE(score,0) FROM security_events ORDER BY id DESC LIMIT 1000`)
	if err != nil {
		return
	}
	defer rows.Close()

	var currentSum [30]float64
	var currentCount int
	for rows.Next() {
		var score float64
		if err := rows.Scan(&score); err == nil {
			if currentCount < 3000 {
				currentSum[currentCount%30] += score
			}
			currentCount++
		}
	}
	if currentCount == 0 {
		return
	}

	maxZ := 0.0
	for _, gs := range gammaStats.Stats {
		if gs.FeatureIdx >= 30 || gs.Count == 0 {
			continue
		}
		currentMean := currentSum[gs.FeatureIdx] / float64(min(currentCount, 30))
		variance := gs.M2 / float64(gs.Count)
		stddev := math.Sqrt(math.Abs(variance))
		if stddev < 0.0001 {
			continue
		}
		zScore := math.Abs(currentMean-gs.Mean) / stddev
		if zScore > maxZ {
			maxZ = zScore
		}
		if zScore > 3.0 {
			s.DriftDetected = true
			s.DriftZScore = zScore
			alert(fmt.Sprintf("DRIFT_DETECTED z=%.2f (threshold=3.0)", zScore))
			return
		}
	}
	s.DriftDetected = false
	s.DriftZScore = maxZ
}

func retrainGamma(s *State) {
	d, err := sql.Open("sqlite", BrainDB+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return
	}
	defer d.Close()

	rows, err := d.Query(`SELECT COALESCE(features,''), COALESCE(score,0)
		FROM security_events WHERE tcp_ttl > 0
		ORDER BY id DESC LIMIT ?`, ReplayCount)
	if err != nil {
		return
	}
	defer rows.Close()

	type sample struct {
		features []float64
		score    float64
	}
	var samples []sample
	for rows.Next() {
		var featuresStr string
		var score float64
		if err := rows.Scan(&featuresStr, &score); err == nil {
			features := parseFeatureString(featuresStr)
			if len(features) >= 8 {
				samples = append(samples, sample{features: features, score: score})
			}
		}
	}
	if len(samples) < 10 {
		return
	}

	n := len(samples)
	dim := 8
	means := make([]float64, dim)
	for _, s := range samples {
		for i := 0; i < dim && i < len(s.features); i++ {
			means[i] += s.features[i]
		}
	}
	for i := range means {
		means[i] /= float64(n)
	}

	weights := make([]float64, dim)
	for i := 0; i < dim; i++ {
		if means[i] > 0.001 {
			weights[i] = 1.0 / means[i]
		} else {
			weights[i] = 1.0
		}
	}
	total := 0.0
	for _, w := range weights {
		total += w
	}
	if total > 0 {
		for i := range weights {
			weights[i] /= total
		}
	}

	s.GammaWeights = weights

	out, _ := json.MarshalIndent(map[string]interface{}{
		"weights":     weights,
		"train_samples": n,
		"trained_at":  time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	os.WriteFile(GammaStats, out, 0644)

	replayed := 0
	mismatches := 0
	for _, samp := range samples {
		score := 0.0
		for i := 0; i < dim && i < len(samp.features); i++ {
			score += samp.features[i] * weights[i]
		}
		if len(weights) > 0 {
			score /= float64(len(weights))
		}
		if (score >= Threshold) != (samp.score >= Threshold) {
			mismatches++
		}
		replayed++
	}
	log.Printf("Gamma retrained: %d samples, weights=%v, replay=%d mismatches=%d",
		n, fmtWeights(weights), replayed, mismatches)

	if mismatches > 0 {
		alert(fmt.Sprintf("RETRAIN_REGRESSION replay=%d mismatches=%d", replayed, mismatches))
	}
}

func fmtWeights(w []float64) string {
	parts := make([]string, len(w))
	for i, v := range w {
		parts[i] = fmt.Sprintf("%.4f", v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func writeStatus(s *State) {
	summary := AuditSummary{
		Status:         "ok",
		Transactions:   s.Transactions,
		Anomalies:      s.Anomalies,
		Mismatches:     s.Mismatches,
		ChainBreaks:    s.ChainBreaks,
		DriftDetected:  s.DriftDetected,
		DriftZScore:    s.DriftZScore,
		IntegrityOK:    s.IntegrityOK,
		ModelIntegrity: ModelIntegrity{
			ShieldHash: trunc(s.ModelHashes["shield"]),
			SoulHash:   trunc(s.ModelHashes["soul"]),
			GammaHash:  trunc(s.ModelHashes["gamma"]),
			ShieldOK:   s.ModelHashes["shield"] != "",
			SoulOK:     s.ModelHashes["soul"] != "",
			GammaOK:    s.ModelHashes["gamma"] != "",
		},
		ServiceHealth: s.Services,
		ChainHead:     trunc(s.CurrentHash),
		LastUpdate:    time.Now().UTC().Format(time.RFC3339),
		UptimeSeconds: int64(time.Since(s.StartTime).Seconds()),
		Version:       "auditor-go-v2",
		GammaWeights: GammaWeights{
			Alpha: WeightAlpha,
			Beta:  WeightBeta,
			Gamma: WeightGamma,
			Phi:   Threshold,
		},
	}
	data, _ := json.MarshalIndent(summary, "", "  ")
	os.MkdirAll("/var/lib/aegis-sigma", 0755)
	os.WriteFile(StatusFile, data, 0644)
}

func serveHTTP(s *State) {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"agent":   "auditor-go",
			"version": "2.0.0",
			"uptime":  time.Since(s.StartTime).Seconds(),
		})
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(StatusFile)
		if err != nil {
			w.WriteHeader(503)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "not ready"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})

	http.HandleFunc("/api/audit/status", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(StatusFile)
		if err != nil {
			w.WriteHeader(503)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "not ready"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	})

	http.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			IP       string    `json:"ip"`
			Features []float64 `json:"features"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		gammaScore := 0.0
		if len(req.Features) >= 8 {
			for i := 0; i < len(req.Features) && i < len(s.GammaWeights); i++ {
				gammaScore += req.Features[i] * s.GammaWeights[i]
			}
			if len(s.GammaWeights) > 0 {
				gammaScore /= float64(len(s.GammaWeights))
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"gamma_score":   gammaScore,
			"threshold":     Threshold,
			"hostile":       gammaScore >= Threshold,
			"chain_head":    trunc(s.CurrentHash),
			"transactions":  s.Transactions,
			"integrity_ok":  s.IntegrityOK,
		})
	})

	http.HandleFunc("/replay", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		go retrainGamma(s)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "retrain triggered",
		})
	})

	http.HandleFunc("/api/audit/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Services)
	})

	if err := http.ListenAndServe(fmt.Sprintf(":%d", Port), nil); err != nil {
		log.Fatalf("HTTP listen error: %v", err)
	}
}

func parseEvidence(evidence, key string) float64 {
	if evidence == "" {
		return 0
	}
	var m map[string]interface{}
	if json.Unmarshal([]byte(evidence), &m) != nil {
		return 0
	}
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

func parseFeatureString(featuresStr string) []float64 {
	if featuresStr == "" {
		return nil
	}
	featuresStr = strings.Trim(featuresStr, "[]")
	parts := strings.Split(featuresStr, ",")
	var result []float64
	for _, p := range parts {
		p = strings.TrimSpace(p)
		var v float64
		if _, err := fmt.Sscanf(p, "%f", &v); err == nil {
			result = append(result, v)
		}
	}
	return result
}

func severityToNum(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func alert(msg string) {
	f, err := os.OpenFile(AlertsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().UTC().Format(time.RFC3339), msg)
	log.Printf("ALERT: %s", msg)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// httpCheck exported for service health (not currently used but kept for API surface)
var _ = http.DefaultClient.Get

// Unused but referenced in existing code for compatibility
func isolationScore(features []float64) float64 {
	if len(features) == 0 {
		return 0
	}
	score := 0.0
	count := 0

	if features[0] < 0.15 {
		score += 0.8
		count++
	}
	if len(features) > 1 && features[1] < 0.015 {
		score += 0.7
		count++
	}
	if len(features) > 2 && features[2] < 0.01 {
		score += 0.6
		count++
	}
	if len(features) > 3 && features[3] < 0.5 {
		score += 0.9
		count++
	}

	if count == 0 {
		return 0.05
	}
	return math.Min(score/float64(count), 1.0)
}
