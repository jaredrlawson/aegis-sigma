package synaptic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// URIEL state machine — each strike pushes the URIEL index forward through the
// Fibonacci sequence. disharmony_score accumulates as the actor's behavioral
// fingerprint diverges from prior visits.

// RecordMemorize persists per-IP long-term memory into synaptic_memory.
// Called by the clusterer and by the Shield after a strike.
func RecordMemorize(ip, ua, path, country, threatLevel, behavioralDNA, ja3Fingerprint, hardwareSignature string, strikes int) {
	if ip == "" {
		return
	}
	signature := signature(ip, ua, path)
	uriel := urielState(strikes)
	disharmony := disharmonyScore(strikes, behavioralDNA, hardwareSignature)

	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var existing int
	d.QueryRow("SELECT COUNT(*) FROM synaptic_memory WHERE signature = ?", signature).Scan(&existing)
	if existing == 0 {
		d.Exec(`INSERT INTO synaptic_memory
			(signature, ip, country, threat_level, soul_reasoning, fractal_pattern,
			 behavioral_dna, strike_count, uriel_state, disharmony_score,
			 ja3_fingerprint, hardware_signature, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			signature, ip, country, threatLevel, behavioralDNA,
			hardwareSignature, behavioralDNA, strikes, uriel, disharmony,
			ja3Fingerprint, hardwareSignature, now, now)
		return
	}
	d.Exec(`UPDATE synaptic_memory SET
		country = ?, threat_level = ?, behavioral_dna = ?,
		strike_count = strike_count + ?, uriel_state = ?,
		disharmony_score = ?, last_seen = ?,
		ja3_fingerprint = COALESCE(?, ja3_fingerprint),
		hardware_signature = COALESCE(?, hardware_signature)
		WHERE signature = ?`,
		country, threatLevel, behavioralDNA, strikes, uriel, disharmony,
		now, ja3Fingerprint, hardwareSignature, signature)
}

// Blackhole denotes an IP as blackholed for the given duration in synaptic memory.
func Blackhole(ip string, durationHours int) {
	until := time.Now().UTC().Add(time.Duration(durationHours) * time.Hour).Format(time.RFC3339)
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	d.Exec("UPDATE synaptic_memory SET is_blackholed = 1, blackhole_until = ? WHERE ip = ?", until, ip)
}

func Lookup(ip string) (signature, country, threatLevel string, strikes int, uriel int, disharmony float64, blackholed bool, firstSeen, lastSeen string) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	var bh int
	var until string
	d.QueryRow(`SELECT signature, country, threat_level, COALESCE(strike_count,0), COALESCE(uriel_state,21),
		COALESCE(disharmony_score,0), COALESCE(is_blackholed,0), COALESCE(blackhole_until,''),
		first_seen, last_seen FROM synaptic_memory WHERE ip = ? ORDER BY last_seen DESC LIMIT 1`, ip).
		Scan(&signature, &country, &threatLevel, &strikes, &uriel, &disharmony, &bh, &until, &firstSeen, &lastSeen)
	if bh == 1 {
		blackholed = true
		if until != "" && until < time.Now().UTC().Format(time.RFC3339) {
			blackholed = false
		}
	}
	return
}

// All returns synaptic rows for the dashboard (most-recently-active first).
func All(limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 100
	}
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT ip, country, threat_level, COALESCE(behavioral_dna,''),
		COALESCE(strike_count,0), COALESCE(uriel_state,21), COALESCE(disharmony_score,0),
		COALESCE(is_blackholed,0), COALESCE(blackhole_until,''),
		first_seen, last_seen, COALESCE(ja3_fingerprint,''), COALESCE(hardware_signature,'')
		FROM synaptic_memory ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var ip, country, threat, behavioral, first, last, ja3, hw, bhUntil string
		var strikes, uriel, bh int
		var disharmony float64
		rows.Scan(&ip, &country, &threat, &behavioral, &strikes, &uriel, &disharmony, &bh, &bhUntil, &first, &last, &ja3, &hw)
		out = append(out, map[string]interface{}{
			"ip":               ip,
			"country":          country,
			"threat_level":     threat,
			"behavioral_dna":   behavioral,
			"strike_count":     strikes,
			"uriel_state":      uriel,
			"disharmony_score": disharmony,
			"is_blackholed":    bh == 1,
			"blackhole_until":  bhUntil,
			"first_seen":       first,
			"last_seen":        last,
			"ja3":              ja3,
			"hardware":         hw,
		})
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}

func Count() int {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0
	}
	defer d.Close()
	var n int
	d.QueryRow("SELECT COUNT(*) FROM synaptic_memory").Scan(&n)
	return n
}

// signature merges IP + UA-family + path-intent so re-attacks from the same
// host with the same tooling produce a stable signature.
func signature(ip, ua, path string) string {
	uaFam := uaFamily(ua)
	intent := pathIntent(path)
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s|%s|%s", ip, uaFam, intent)))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// urielState advances through the Fibonacci pattern based on strike count.
// Each strike shifts the URIEL index by 1 along the sequence.
var fibSeq = []int{21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181}

func urielState(strikes int) int {
	if strikes < 0 {
		strikes = 0
	}
	if strikes >= len(fibSeq) {
		return fibSeq[len(fibSeq)-1]
	}
	return fibSeq[strikes]
}

func disharmonyScore(strikes int, behDNA, hwSig string) float64 {
	// Higher disharmony = more deviation from a stable actor pattern.
	// Detected hardware changes or strikes bump this up.
	score := float64(strikes) * 0.15
	if behDNA == "" {
		score += 0.1
	}
	if hwSig == "" {
		score += 0.1
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func uaFamily(ua string) string {
	l := lowerASCII(ua)
	switch {
	case contains(l, "nmap"):
		return "nmap"
	case contains(l, "masscan"), contains(l, "zmap"):
		return "scanner"
	case contains(l, "sqlmap"):
		return "sqlmap"
	case contains(l, "curl"), contains(l, "wget"):
		return "cli"
	case contains(l, "python"):
		return "python"
	case contains(l, "chrome"), contains(l, "safari"), contains(l, "firefox"):
		return "browser"
	default:
		return "unknown"
	}
}

func pathIntent(path string) string {
	p := lowerASCII(path)
	switch {
	case contains(p, ".git"):
		return "git-exposure"
	case contains(p, ".env"):
		return "env-exposure"
	case contains(p, "wp-admin"), contains(p, "wp-login"):
		return "wp-brute"
	case contains(p, "xmlrpc"):
		return "xmlrpc"
	case contains(p, "phpmyadmin"), contains(p, "adminer"):
		return "dbadmin"
	case contains(p, "actuator"):
		return "spring"
	case contains(p, "console"), contains(p, "phpinfo"):
		return "infoleak"
	default:
		return "probe"
	}
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
