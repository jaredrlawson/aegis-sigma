package clusterer

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Cluster represents a group of attacker IPs sharing TTPs / ASN / timing.
type Cluster struct {
	ClusterID      string   `json:"cluster_id"`
	IPs            []string `json:"ips"`
	Attribution    string   `json:"attribution"`
	RiskScore      float64  `json:"risk_score"`
	FibonacciTier  string   `json:"fibonacci_tier"` // F1, F2, F5, F8
	TotalAttacks   int      `json:"total_attacks"`
	IPCount        int      `json:"ip_count"`
	Countries      []string `json:"countries"`
	IntentPatterns []string `json:"intent_patterns"`
	ASN            string   `json:"asn"`
	ToolSignature  string   `json:"tool_signature"`
	ActorType      string   `json:"actor_type"`
	LastActive     string   `json:"last_active"`
	MasterActorUUID string  `json:"master_actor_uuid"`
}

// ActorSummary is the per-actor rollup we return to the dashboard.
type ActorSummary struct {
	MasterActor    string   `json:"masterActor"`
	TotalAttacks   int      `json:"totalAttacks"`
	IPCount        int      `json:"ipCount"`
	IPs            []string `json:"ips"`
	Countries      []string `json:"countries"`
	IntentPatterns []string `json:"intentPatterns"`
	Severity       string   `json:"severity"`
	Tier           string   `json:"tier"`
	FirstSeen      string   `json:"firstSeen"`
	Fingerprint    string   `json:"fingerprint"`
	ThreatScore    float64  `json:"threatScore"`
	ThreatLevel    string   `json:"threatLevel"`
	ThreatLabel    string   `json:"threatLabel"`
	TargetVectors  []string `json:"targetVectors"`
	TopUris        []string `json:"topUris"`
	Sites          []string `json:"sites"`
	ThreatResonance float64 `json:"threatResonance"`
}

// AttributionResult is the dashboard payload for attribution.js.
type AttributionResult struct {
	MasterActor   *ActorSummary   `json:"masterActor"`
	Lieutenants   []*ActorSummary `json:"lieutenants"`
	Tools         []*ActorSummary `json:"tools"`
	Scans         []*ActorSummary `json:"scans"`
	All           []*ActorSummary `json:"all"`
	TotalClusters int             `json:"totalClusters"`
	TotalAttacks  int             `json:"totalAttacks"`
}

// eventRow is a flattened projection of security_events for clustering.
type eventRow struct {
	IP          string
	Reason      string
	Severity    string
	UserAgent   string
	RequestURI  string
	ISPA        string
	CountryCode string
	Fingerprint string
	AgencyID    string
	Strikes     int
	CreatedAt   string
}

// toolFamily reduces a raw UA string to a coarse tool family.
func toolFamily(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "nmap"):
		return "nmap"
	case strings.Contains(l, "masscan"):
		return "masscan"
	case strings.Contains(l, "zgrab"):
		return "zgrab"
	case strings.Contains(l, "nikto"):
		return "nikto"
	case strings.Contains(l, "sqlmap"):
		return "sqlmap"
	case strings.Contains(l, "gobuster"):
		return "gobuster"
	case strings.Contains(l, "wpscan"):
		return "wpscan"
	case strings.Contains(l, "l9scan"), strings.Contains(l, "leakix"):
		return "l9scan"
	case strings.Contains(l, "acunetix"):
		return "acunetix"
	case strings.Contains(l, "zmap"):
		return "zmap"
	case strings.Contains(l, "shodan"):
		return "shodan"
	case strings.Contains(l, "curl"):
		return "curl"
	case strings.Contains(l, "wget"):
		return "wget"
	case strings.Contains(l, "python-requests"), strings.Contains(l, "python/"):
		return "python-http"
	case strings.Contains(l, "go-http"):
		return "go-http"
	case strings.Contains(l, "java/"):
		return "java-http"
	case strings.Contains(l, "deepseekbot"):
		return "deepseekbot"
	case strings.Contains(l, "oai-searchbot"):
		return "oai-searchbot"
	case strings.Contains(l, "claudebot"):
		return "claudebot"
	case strings.Contains(l, "chrome"), strings.Contains(l, "safari"), strings.Contains(l, "firefox"):
		return "browser"
	default:
		return "unknown"
	}
}

// intentCategory reduces a request URI / reason into a TTP intent tag.
func intentCategory(uri, reason string) string {
	uriL := strings.ToLower(uri)
	switch {
	case strings.Contains(uriL, ".git"):
		return "git-exposure"
	case strings.Contains(uriL, ".env"):
		return "env-exposure"
	case strings.Contains(uriL, ".aws"):
		return "cloud-cred-theft"
	case strings.Contains(uriL, "wp-admin"), strings.Contains(uriL, "wp-login"):
		return "wp-brute"
	case strings.Contains(uriL, "xmlrpc"):
		return "xmlrpc-abuse"
	case strings.Contains(uriL, "phpmyadmin"), strings.Contains(uriL, "adminer"):
		return "db-admin-probe"
	case strings.Contains(uriL, "actuator"), strings.Contains(uriL, "heapdump"):
		return "spring-probe"
	case strings.Contains(uriL, "console"), strings.Contains(uriL, "server-info"), strings.Contains(uriL, "phpinfo"):
		return "info-leak"
	case strings.Contains(uriL, "server-status"):
		return "status-probe"
	case strings.Contains(uriL, "backup"), strings.Contains(uriL, "database.sql"), strings.Contains(uriL, ".sql"):
		return "db-exfil"
	case strings.Contains(uriL, "jenkins"), strings.Contains(uriL, "gitlab"), strings.Contains(uriL, "cpanel"):
		return "admin-console-probe"
	case strings.HasPrefix(reason, "HONEYPOT"):
		return "honeypot-probe"
	case strings.HasPrefix(reason, "TOR"):
		return "tor-exit-probe"
	case strings.HasPrefix(reason, "PATH_BLOCK"):
		return "path-hostile"
	case strings.HasPrefix(reason, "CONSENSUS"):
		return "triad-consensus-block"
	default:
		return "unknown"
	}
}

// clusterKey builds the grouping key for an event row.
// We cluster by: ASN (or country if ASN empty) + tool family + top intent.
// This produces campaigns of attackers using the same tool from the same network
// against the same target pattern.
func clusterKey(e eventRow) string {
	asn := e.ISPA
	if asn == "" || asn == "NA" {
		asn = "CC:" + e.CountryCode
		if asn == "CC:" {
			asn = "UNKNOWN"
		}
	}
	tool := toolFamily(e.UserAgent)
	intent := intentCategory(e.RequestURI, e.Reason)
	return fmt.Sprintf("%s|%s|%s", asn, tool, intent)
}

// fibTier assigns the 6-level Fibonacci hierarchy label:
//   F1 = Master Actor (most strikes, biggest campaign)
//   F2 = Lieutenant (significant campaign)
//   F5 = Tool (single-tool cluster)
//   F8 = Scan (lone scanner / one-off)
func fibTier(rank, totalClusters int, attacks int) string {
	if totalClusters == 0 {
		return "F8"
	}
	pct := float64(rank) / float64(totalClusters)
	switch {
	case rank == 0 && attacks >= 50:
		return "F1"
	case pct < 0.1 && attacks >= 20:
		return "F1"
	case pct < 0.3 && attacks >= 10:
		return "F2"
	case attacks >= 5:
		return "F5"
	default:
		return "F8"
	}
}

// masterUUID builds a deterministic UUID for a cluster key.
func masterUUID(key string) string {
	h := sha256.Sum256([]byte("aegis-cluster:" + key))
	return fmt.Sprintf("AEGIS-CL-%X", h[:8])
}

// loadEvents pulls events from the lookback window out of brain.sqlite.
func loadEvents(d *sql.DB, lookback time.Duration) ([]eventRow, error) {
	cutoff := time.Now().UTC().Add(-lookback).Format("2006-01-02 15:04:05")
	rows, err := d.Query(`SELECT ip, reason, severity, user_agent, request_uri,
		COALESCE(isp_asn, ''), COALESCE(country_code, ''),
		COALESCE(fingerprint, ''), COALESCE(agency_id, ''),
		COALESCE(strikes, 1), created_at
		FROM security_events
		WHERE created_at >= ?
		ORDER BY id ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []eventRow
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.IP, &e.Reason, &e.Severity, &e.UserAgent, &e.RequestURI,
			&e.ISPA, &e.CountryCode, &e.Fingerprint, &e.AgencyID,
			&e.Strikes, &e.CreatedAt); err != nil {
			continue
		}
		if e.UserAgent == "" {
			e.UserAgent = "unknown"
		}
		events = append(events, e)
	}
	return events, nil
}

// groupEvents buckets events by clusterKey and builds cluster aggregates.
func groupEvents(events []eventRow) map[string]*Cluster {
	clusters := map[string]*Cluster{}
	for _, e := range events {
		key := clusterKey(e)
		c, ok := clusters[key]
		if !ok {
			c = &Cluster{
				ClusterID:      key,
				IPs:            []string{},
				Countries:      []string{},
				IntentPatterns: []string{},
				ASN:            e.ISPA,
				ToolSignature:  toolFamily(e.UserAgent),
				MasterActorUUID: masterUUID(key),
			}
			clusters[key] = c
		}
		c.TotalAttacks++
		found := false
		for _, ip := range c.IPs {
			if ip == e.IP {
				found = true
				break
			}
		}
		if !found {
			c.IPs = append(c.IPs, e.IP)
		}
		found = false
		for _, cc := range c.Countries {
			if cc == e.CountryCode || (cc == "" && e.CountryCode == "") {
				found = true
				break
			}
		}
		if !found && e.CountryCode != "" {
			c.Countries = append(c.Countries, e.CountryCode)
		}
		intent := intentCategory(e.RequestURI, e.Reason)
		found = false
		for _, p := range c.IntentPatterns {
			if p == intent {
				found = true
				break
			}
		}
		if !found {
			c.IntentPatterns = append(c.IntentPatterns, intent)
		}
		if e.Severity == "critical" || e.Severity == "high" {
			c.Attribution = "hostile"
		}
		if e.CreatedAt > c.LastActive {
			c.LastActive = e.CreatedAt
		}
	}
	return clusters
}

// scoreCluster computes a 0..1 risk score from strike volume + IP spread + country spread.
func scoreCluster(c *Cluster, maxAttacks int) float64 {
	if maxAttacks == 0 {
		return 0
	}
	attackScore := float64(c.TotalAttacks) / float64(maxAttacks)
	ipSpread := float64(len(c.IPs)) / 50.0
	if ipSpread > 1.0 {
		ipSpread = 1.0
	}
	geoSpread := float64(len(c.Countries)) / 10.0
	if geoSpread > 1.0 {
		geoSpread = 1.0
	}
	score := 0.55*attackScore + 0.30*ipSpread + 0.15*geoSpread
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// RunClustering is the main entry — reads recent events, builds clusters,
// writes to actor_clusters, and back-fills master_actor_uuid on
// security_events + forensic_reports.
func RunClustering(lookback time.Duration) (*AttributionResult, error) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return nil, err
	}
	defer d.Close()

	events, err := loadEvents(d, lookback)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return &AttributionResult{
			MasterActor:   nil,
			Lieutenants:   []*ActorSummary{},
			Tools:         []*ActorSummary{},
			Scans:         []*ActorSummary{},
			All:           []*ActorSummary{},
			TotalClusters: 0,
			TotalAttacks:  0,
		}, nil
	}

	clusters := groupEvents(events)

	maxAttacks := 0
	for _, c := range clusters {
		if c.TotalAttacks > maxAttacks {
			maxAttacks = c.TotalAttacks
		}
	}

	for _, c := range clusters {
		c.RiskScore = scoreCluster(c, maxAttacks)
		c.IPCount = len(c.IPs)
	}

	sorted := make([]*Cluster, 0, len(clusters))
	for _, c := range clusters {
		sorted = append(sorted, c)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TotalAttacks > sorted[j].TotalAttacks
	})

	totalClusters := len(sorted)
	for i, c := range sorted {
		c.FibonacciTier = fibTier(i, totalClusters, c.TotalAttacks)
		if c.ActorType == "" {
			c.ActorType = c.ToolSignature
		}
	}

	persistClusters(d, sorted)
	backfillMasterActor(d, sorted)

	result := buildAttributionResult(sorted, events)
	return result, nil
}

// persistClusters upserts each cluster into actor_clusters.
func persistClusters(d *sql.DB, clusters []*Cluster) {
	d.Exec("DELETE FROM actor_clusters WHERE cluster_id LIKE 'GO-%'")
	for _, c := range clusters {
		ipStr := strings.Join(c.IPs, ",")
		if len(ipStr) > 9000 {
			ipStr = ipStr[:9000]
		}
		clusterID := "GO-" + c.MasterActorUUID[:min(len(c.MasterActorUUID), 50)]
		attribution := c.Attribution
		if attribution == "" {
			attribution = c.FibonacciTier + ":" + c.ToolSignature
		}
		_, err := d.Exec(`INSERT INTO actor_clusters (cluster_id, ips, attribution, risk_score, last_active)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(cluster_id) DO UPDATE SET
				ips=excluded.ips, attribution=excluded.attribution,
				risk_score=excluded.risk_score, last_active=excluded.last_active`,
			clusterID, ipStr, attribution, c.RiskScore, c.LastActive)
		if err != nil {
			log.Printf("[CLUSTERER] persist error: %v", err)
		}
	}
}

// backfillMasterActor writes master_actor_uuid back onto security_events and
// forensic_reports so the dashboard can join them. Forensic reports also get a
// cluster-level intent_unmasked string assembled from the cluster's intent
// patterns + tool signature + Fibonacci tier.
func backfillMasterActor(d *sql.DB, clusters []*Cluster) {
	for _, c := range clusters {
		if len(c.IPs) == 0 {
			continue
		}
		placeholders := strings.Repeat("?,", len(c.IPs))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]interface{}, 0, len(c.IPs)+1)
		args = append(args, c.MasterActorUUID)
		for _, ip := range c.IPs {
			args = append(args, ip)
		}
		_, _ = d.Exec("UPDATE security_events SET master_actor_uuid = ? WHERE ip IN ("+placeholders+") AND (master_actor_uuid IS NULL OR master_actor_uuid = '')", args...)
		_, _ = d.Exec("UPDATE forensic_reports SET master_actor_uuid = ? WHERE ip IN ("+placeholders+") AND (master_actor_uuid IS NULL OR master_actor_uuid = '')", args...)

		// Cluster-level intent_unmasked — only stamps empty rows so the
		// Shield's real-time LLM call keeps precedence.
		intent := clusterIntentUnmask(c)
		if intent != "" {
			intentArgs := make([]interface{}, 0, len(c.IPs)+1)
			intentArgs = append(intentArgs, intent)
			for _, ip := range c.IPs {
				intentArgs = append(intentArgs, ip)
			}
			_, _ = d.Exec("UPDATE forensic_reports SET intent_unmasked = ? WHERE ip IN ("+placeholders+") AND (intent_unmasked IS NULL OR intent_unmasked = '')", intentArgs...)
		}
	}
}

// clusterIntentUnmask produces a short human-readable intent summary for a
// cluster — used when the Shield's real-time LLM call hasn't stamped a row yet.
func clusterIntentUnmask(c *Cluster) string {
	if len(c.IntentPatterns) == 0 {
		return ""
	}
	intent := strings.Join(c.IntentPatterns, ", ")
	parts := []string{
		"FIB:" + c.FibonacciTier,
		"TOOL:" + c.ToolSignature,
		"INTENT:" + intent,
	}
	if c.IPCount >= 10 {
		parts = append(parts, "campaign")
	} else if c.IPCount >= 3 {
		parts = append(parts, "coordinated")
	} else {
		parts = append(parts, "lone")
	}
	if c.Attribution == "hostile" {
		parts = append(parts, "hostile")
	}
	return strings.Join(parts, " | ")
}

func buildAttributionResult(sorted []*Cluster, events []eventRow) *AttributionResult {
	totalAttacks := len(events)

	summaries := make([]*ActorSummary, 0, len(sorted))
	for _, c := range sorted {
		s := &ActorSummary{
			MasterActor:    c.MasterActorUUID,
			TotalAttacks:   c.TotalAttacks,
			IPCount:        c.IPCount,
			IPs:            c.IPs,
			Countries:      c.Countries,
			IntentPatterns: c.IntentPatterns,
			Severity:       "high",
			Tier:           c.FibonacciTier,
		}
		switch c.FibonacciTier {
		case "F1":
			s.Severity = "critical"
		case "F2":
			s.Severity = "high"
		case "F5":
			s.Severity = "medium"
		default:
			s.Severity = "low"
		}
		summaries = append(summaries, s)
	}

	result := &AttributionResult{
		TotalClusters: len(sorted),
		TotalAttacks:  totalAttacks,
		All:           summaries,
	}

	for _, s := range summaries {
		switch s.Tier {
		case "F1":
			if result.MasterActor == nil || s.TotalAttacks > result.MasterActor.TotalAttacks {
				result.MasterActor = s
			}
		case "F2":
			result.Lieutenants = append(result.Lieutenants, s)
		case "F5":
			result.Tools = append(result.Tools, s)
		case "F8":
			result.Scans = append(result.Scans, s)
		}
	}

	if result.Lieutenants == nil {
		result.Lieutenants = []*ActorSummary{}
	}
	if result.Tools == nil {
		result.Tools = []*ActorSummary{}
	}
	if result.Scans == nil {
		result.Scans = []*ActorSummary{}
	}

	return result
}

// StartLoop runs clustering on a ticker — call as a goroutine.
func StartLoop(interval, lookback time.Duration) {
	log.Printf("[CLUSTERER] starting: interval=%s lookback=%s", interval, lookback)
	RunClustering(lookback)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		result, err := RunClustering(lookback)
		if err != nil {
			log.Printf("[CLUSTERER] error: %v", err)
			continue
		}
		log.Printf("[CLUSTERER] cycle done: clusters=%d attacks=%d master=%s",
			result.TotalClusters, result.TotalAttacks, func() string {
				if result.MasterActor != nil {
					return result.MasterActor.MasterActor
				}
				return "none"
			}())
	}
}

// GetAttribution runs a one-shot clustering pass and returns the dashboard
// payload. Used by the dashboard's /forensic-attribution handler.
func GetAttribution(lookback time.Duration) (*AttributionResult, error) {
	return RunClustering(lookback)
}

// ForensicsSummary returns real counts from brain.sqlite.
func ForensicsSummary() (int, int, error) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0, 0, err
	}
	defer d.Close()
	var secEvents, forensicReports int
	d.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&secEvents)
	d.QueryRow("SELECT COUNT(*) FROM forensic_reports").Scan(&forensicReports)
	return secEvents, forensicReports, nil
}

// FBIEvidenceManifest sums the FBI evidence JSONL by event_type.
func FBIEvidenceManifest() (int, map[string]int, error) {
	data, err := readFile(config.EvidenceFile)
	if err != nil {
		return 0, map[string]int{}, nil
	}
	byType := map[string]int{}
	total := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		et, _ := rec["event_type"].(string)
		if et == "" {
			et = "unknown"
		}
		byType[et]++
		total++
	}
	return total, byType, nil
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
