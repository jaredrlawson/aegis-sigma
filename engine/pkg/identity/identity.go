package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Record stitches a per-IP identity into brain.sqlite's identities table.
// physical_id is derived from TCP fingerprint hash + UA hash (silicon DNA).
// behavioral_dna is the canonical pickle of UA + path family + tool family.
// trust_score decays upward to 1.0 over time when no strikes arrive,
// drops toward 0 on each strike.
func Record(ip, ua, path, tcpFingerprint string, strikes int) {
	if ip == "" {
		return
	}
	physicalID := computePhysicalID(ip, tcpFingerprint, ua)
	behavioralDNA := computeBehavioralDNA(ua, path)

	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()

	var existingStrikes int
	var existingTrust float64
	err = d.QueryRow("SELECT COALESCE(strikes,0), COALESCE(trust_score,0.5) FROM identities WHERE ip = ?", ip).Scan(&existingStrikes, &existingTrust)
	if err != nil {
		// New identity
		trust := 0.5
		if strikes > 0 {
			trust = 0.1
		}
		d.Exec(`INSERT INTO identities (ip, physical_id, silicon_dna, behavioral_dna, trust_score, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			ip, physicalID, tcpFingerprint, behavioralDNA, trust,
			time.Now().UTC().Format("2006-01-02 15:04:05"),
			time.Now().UTC().Format("2006-01-02 15:04:05"))
		_, _ = d.Exec("UPDATE identities SET strikes = ? WHERE ip = ?", strikes, ip)
		return
	}

	// Existing — decay trust score: each strike pushes toward 0,
	// time since last strike pushes back up.
	totalStrikes := existingStrikes + strikes
	// trust = max(0, 1 - strikes*0.15) clamped to [0, 1]
	newTrust := 1.0 - float64(totalStrikes)*0.15
	if newTrust < 0 {
		newTrust = 0
	}
	if newTrust > 1 {
		newTrust = 1
	}
	_, _ = d.Exec(`UPDATE identities SET
		physical_id = ?, silicon_dna = ?, behavioral_dna = ?,
		trust_score = ?, last_seen = ?, strikes = ?
		WHERE ip = ?`,
		physicalID, tcpFingerprint, behavioralDNA, newTrust,
		time.Now().UTC().Format("2006-01-02 15:04:05"),
		totalStrikes, ip)
}

func computePhysicalID(ip, tcpFingerprint, ua string) string {
	h := sha256.New()
	h.Write([]byte(ip + ":" + tcpFingerprint + ":" + ua[:min(len(ua), 50)]))
	return "SID-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func computeBehavioralDNA(ua, path string) string {
	uaFam := toolFamily(ua)
	intent := pathIntent(path)
	h := sha256.New()
	h.Write([]byte(uaFam + "|" + intent))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func toolFamily(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "nmap"):
		return "nmap"
	case strings.Contains(l, "masscan"), strings.Contains(l, "zmap"):
		return "scanner"
	case strings.Contains(l, "sqlmap"):
		return "sqlmap"
	case strings.Contains(l, "nikto"), strings.Contains(l, "gobuster"):
		return "web-scanner"
	case strings.Contains(l, "curl"), strings.Contains(l, "wget"):
		return "cli-http"
	case strings.Contains(l, "python"):
		return "python-http"
	case strings.Contains(l, "chrome"), strings.Contains(l, "safari"), strings.Contains(l, "firefox"):
		return "browser"
	default:
		return "unknown"
	}
}

func pathIntent(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, ".git"):
		return "git-exposure"
	case strings.Contains(p, ".env"):
		return "env-exposure"
	case strings.Contains(p, "wp-admin"), strings.Contains(p, "wp-login"):
		return "wp-brute"
	case strings.Contains(p, "xmlrpc"):
		return "xmlrpc-abuse"
	case strings.Contains(p, "phpmyadmin"), strings.Contains(p, "adminer"):
		return "db-admin-probe"
	case strings.Contains(p, "actuator"), strings.Contains(p, "heapdump"):
		return "spring-exploit"
	case strings.Contains(p, "console"), strings.Contains(p, "phpinfo"):
		return "info-leak"
	case strings.Contains(p, "admin"):
		return "admin-probe"
	default:
		return "path-probe"
	}
}

// Lookup returns the identity row for an IP, used by dashboard dossier.
func Lookup(ip string) (physicalID, siliconDNA, behavioralDNA string, trust float64, firstSeen, lastSeen string) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	var ts, ls string
	d.QueryRow("SELECT physical_id, silicon_dna, behavioral_dna, trust_score, first_seen, last_seen FROM identities WHERE ip = ?", ip).
		Scan(&physicalID, &siliconDNA, &behavioralDNA, &trust, &ts, &ls)
	if ts != "" {
		firstSeen = ts
	}
	if ls != "" {
		lastSeen = ls
	}
	return
}

// All returns all identities for the dashboard.
func All() []map[string]interface{} {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT ip, physical_id, silicon_dna, behavioral_dna, trust_score, first_seen, last_seen,
		COALESCE(strikes,0) FROM identities ORDER BY trust_score ASC, last_seen DESC LIMIT 200`)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var ip, pid, silicon, behavioral, first, last string
		var trust float64
		var strikes int
		rows.Scan(&ip, &pid, &silicon, &behavioral, &trust, &first, &last, &strikes)
		out = append(out, map[string]interface{}{
			"ip":             ip,
			"physical_id":    pid,
			"silicon_dna":    silicon,
			"behavioral_dna": behavioral,
			"trust_score":    trust,
			"strikes":        strikes,
			"first_seen":     first,
			"last_seen":      last,
		})
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}

func CurrentIdentityCount() int {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0
	}
	defer d.Close()
	var n int
	d.QueryRow("SELECT COUNT(*) FROM identities").Scan(&n)
	return n
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// init forces the strikes column to exist if migrations altered the schema
func init() {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	_, _ = d.Exec("ALTER TABLE identities ADD COLUMN strikes INTEGER DEFAULT 0")
}

// FormatIdentity renders a human-readable identity summary.
func FormatIdentity(ip string) string {
	pid, silicon, behavioral, trust, first, _ := Lookup(ip)
	if pid == "" {
		return fmt.Sprintf("[IDENTITY] %s unknown", ip)
	}
	return fmt.Sprintf("[IDENTITY] %s pid=%s trust=%.2f strikes-family=%s dna=%s first=%s",
		ip, pid, trust, silicon[:8], behavioral[:8], first[:10])
}
