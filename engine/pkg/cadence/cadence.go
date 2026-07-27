package cadence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Cadence tracks per-site request timing and harmonic delay. Each visit records
// a fib_sequence_id, request_hash, arrival_micros, harmonic_delay_ms, and
// whether the visitor passed authentication. Periodically the per-site
// cadence_history row is updated.

// RecordVisit logs one request timing entry and updates the site's cadence
// history. Returns the harmonic delay (ms) the system should impose — φ-derived
// from the rolling inter-arrival average.
func RecordVisit(siteID, requestPath string, arrivalMicros int64, isAuthed bool) int {
	if siteID == "" {
		siteID = "global"
	}
	reqHash := hashRequest(siteID, requestPath, arrivalMicros)

	// Rolling φ-harmonic delay — derived from the rolling average inter-arrival.
	recent, avgMicros := rollingAvg(siteID)
	delay := harmonicDelay(avgMicros)

	d, err := db.Open(config.BrainDB)
	if err != nil {
		return delay
	}
	defer d.Close()

	authed := 0
	if isAuthed {
		authed = 1
	}
	d.Exec(`INSERT INTO request_timing
		(fib_sequence_id, request_hash, arrival_micros, harmonic_delay_ms,
		 is_authenticated, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		fibSeqIDForLen(recent+1), reqHash, fmt.Sprintf("%d", arrivalMicros), delay, authed)

	// Update cadence_history for the site with new timestamps blob
	var timestamps string
	d.QueryRow("SELECT COALESCE(timestamps,'') FROM cadence_history WHERE site_id = ?", siteID).Scan(&timestamps)
	ts := time.Now().UTC().Format(time.RFC3339)
	if timestamps == "" {
		timestamps = ts
	} else {
		// Cap stored timestamps to the last 500
		parts := splitLimit(timestamps, ",", 500)
		parts = append(parts, ts)
		timestamps = joinStrings(parts, ",")
	}
	d.Exec(`INSERT INTO cadence_history (site_id, timestamps, updated_at)
		VALUES (?, ?, datetime('now'))
		ON CONFLICT(site_id) DO UPDATE SET timestamps=excluded.timestamps, updated_at=datetime('now')`,
		siteID, timestamps)

	return delay
}

// All returns recent cadence entries for the dashboard.
func All() []map[string]interface{} {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT id, fib_sequence_id, request_hash, arrival_micros,
		harmonic_delay_ms, is_authenticated, created_at
		FROM request_timing ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, authed, delay int
		var fibID, hash, arrMus, ts string
		rows.Scan(&id, &fibID, &hash, &arrMus, &delay, &authed, &ts)
		out = append(out, map[string]interface{}{
			"id":                 id,
			"fib_sequence_id":    fibID,
			"request_hash":       hash,
			"arrival_micros":     arrMus,
			"harmonic_delay_ms":  delay,
			"is_authenticated":   authed == 1,
			"created_at":         ts,
		})
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}

func Sites() []map[string]interface{} {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT site_id, timestamps, created_at, updated_at
		FROM cadence_history ORDER BY updated_at DESC LIMIT 100`)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var siteID, ts, created, updated string
		rows.Scan(&siteID, &ts, &created, &updated)
		count := 1
		if ts != "" {
			for _, c := range ts {
				if c == ',' {
					count++
				}
			}
		}
		out = append(out, map[string]interface{}{
			"site_id":      siteID,
			"visit_count":  count,
			"created_at":   created,
			"updated_at":   updated,
		})
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}

func rollingAvg(siteID string) (int, int64) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0, 0
	}
	defer d.Close()
	var n int
	var sum int64
	d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CAST(arrival_micros AS INTEGER)),0)
		FROM request_timing WHERE fib_sequence_id LIKE ?`, siteID+"%").Scan(&n, &sum)
	// fallback if no rows yet for this site
	if n == 0 {
		return 0, 0
	}
	return n, sum / int64(n)
}

// harmonicDelay derives a φ-multiple delay from average inter-arrival time.
// Delay (ms) = avg_inter_arrival_secs * 1000 / φ, clamped to [10, 5000].
// Faster attackers get a longer delay (tarpit-style throttle).
func harmonicDelay(avgMicros int64) int {
	if avgMicros <= 0 {
		return 100
	}
	avgMS := avgMicros / 1000
	if avgMS <= 0 {
		avgMS = 1
	}
	delay := int(float64(avgMS) * 1000.0 / 1.618033988749895)
	if delay < 10 {
		delay = 10
	}
	if delay > 5000 {
		delay = 5000
	}
	return delay
}

var fibSeq = []int{21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765}

func fibSeqIDForLen(n int) string {
	if n < 0 {
		n = 0
	}
	if n >= len(fibSeq) {
		n = len(fibSeq) - 1
	}
	return fmt.Sprintf("FIB-%d", fibSeq[n])
}

func hashRequest(siteID, path string, arrMicros int64) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s|%s|%d", siteID, path, arrMicros)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func splitLimit(s, sep string, max int) []string {
	out := []string{}
	start := 0
	count := 0
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			out = append(out, s[start:i])
			start = i + len(sep)
			count++
			if count >= max-1 {
				break
			}
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += sep + p
	}
	return out
}
