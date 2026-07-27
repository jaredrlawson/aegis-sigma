package profiler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

type AttackerProfile struct {
	IP              string    `json:"ip"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	HitCount        int       `json:"hit_count"`
	Paths           []string  `json:"paths"`
	UserAgents      []string  `json:"user_agents"`
	ThreatLevel     string    `json:"threat_level"`
	ActorType       string    `json:"actor_type"`
	Fingerprint     string    `json:"fingerprint"`
	GeoCountry      string    `json:"geo_country"`
	GeoASN          string    `json:"geo_asn"`
	BehavioralDNA   string    `json:"behavioral_dna"`
	SessionDuration int       `json:"session_duration_seconds"`
	StrikeCount     int       `json:"strike_count"`
	Blocked         bool      `json:"blocked"`
}

var (
	profiles = map[string]*AttackerProfile{}
	mu       sync.RWMutex
)

func Track(ip, ua, path, country, asn string) {
	mu.Lock()
	defer mu.Unlock()

	p, exists := profiles[ip]
	if !exists {
		p = &AttackerProfile{
			IP:          ip,
			FirstSeen:   time.Now(),
			ActorType:   classifyActor(ua),
			GeoCountry:  country,
			GeoASN:      asn,
			BehavioralDNA: generateBehavioralDNA(ip, ua, path),
		}
		profiles[ip] = p
	}

	p.LastSeen = time.Now()
	p.HitCount++
	p.SessionDuration = int(p.LastSeen.Sub(p.FirstSeen).Seconds())

	if len(p.Paths) < 100 {
		p.Paths = append(p.Paths, path)
	}
	if len(p.UserAgents) < 10 {
		uaExists := false
		for _, u := range p.UserAgents {
			if u == ua {
				uaExists = true
				break
			}
		}
		if !uaExists {
			p.UserAgents = append(p.UserAgents, ua[:min(len(ua), 100)])
		}
	}

	if p.HitCount >= 50 {
		p.ThreatLevel = "critical"
	} else if p.HitCount >= 20 {
		p.ThreatLevel = "high"
	} else if p.HitCount >= 5 {
		p.ThreatLevel = "medium"
	} else {
		p.ThreatLevel = "low"
	}

	if p.HitCount > 0 && p.HitCount%10 == 0 {
		saveProfile(p)
	}
}

func RecordStrike(ip string) {
	mu.Lock()
	defer mu.Unlock()
	if p, ok := profiles[ip]; ok {
		p.StrikeCount++
		p.Blocked = true
		saveProfile(p)
	}
}

func GetProfile(ip string) *AttackerProfile {
	mu.RLock()
	defer mu.RUnlock()
	return profiles[ip]
}

// GetStrikeCount returns the strike count for an IP from the in-memory profiles.
// Used by the PoW challenge handler to derive difficulty.
func GetStrikeCount(ip string) int {
	mu.RLock()
	defer mu.RUnlock()
	if p, ok := profiles[ip]; ok {
		return p.StrikeCount
	}
	return 0
}

func GetStats() map[string]interface{} {
	mu.RLock()
	defer mu.RUnlock()
	total := len(profiles)
	critical := 0
	high := 0
	for _, p := range profiles {
		if p.ThreatLevel == "critical" {
			critical++
		} else if p.ThreatLevel == "high" {
			high++
		}
	}
	return map[string]interface{}{
		"total_profiles":    total,
		"critical":          critical,
		"high":              high,
		"total_hits":        totalHits(),
		"total_strikes":     totalStrikes(),
	}
}

func totalHits() int {
	total := 0
	for _, p := range profiles {
		total += p.HitCount
	}
	return total
}

func totalStrikes() int {
	total := 0
	for _, p := range profiles {
		total += p.StrikeCount
	}
	return total
}

func classifyActor(ua string) string {
	lower := ua
	if containsAny(lower, "nmap", "masscan", "zmap", "shodan") {
		return "SCANNER"
	}
	if containsAny(lower, "sqlmap", "nikto", "gobuster", "metasploit") {
		return "EXPLOIT"
	}
	if containsAny(lower, "mirai", "mozi", "gafgyt") {
		return "BOTNET"
	}
	if containsAny(lower, "curl", "wget", "python-requests", "go-http") {
		return "HTTP_CLIENT"
	}
	return "UNKNOWN"
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func generateBehavioralDNA(ip, ua, path string) string {
	data := fmt.Sprintf("%s:%s:%s", ip, ua, path)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

func saveProfile(p *AttackerProfile) {
	f, err := os.OpenFile(config.EvidenceDir+"/attacker-profiles.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	data, _ := json.Marshal(p)
	f.Write(data)
	f.WriteString("\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
