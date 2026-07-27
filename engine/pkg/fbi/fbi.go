package fbi

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/internal/types"
)

var (
	lastHash = "GENESIS"
	mu       sync.Mutex
)

func Init() {
	os.MkdirAll(config.EvidenceDir, 0755)
	data, err := os.ReadFile(config.EvidenceFile)
	if err != nil {
		return
	}
	lines := splitLines(string(data))
	if len(lines) > 0 {
		var last map[string]interface{}
		if json.Unmarshal([]byte(lines[len(lines)-1]), &last) == nil {
			if h, ok := last["evidence_chain_hash"].(string); ok {
				lastHash = h
			}
		}
	}
}

func WriteEvidence(event types.FBIEvidence) string {
	mu.Lock()
	defer mu.Unlock()

	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	caseID := fmt.Sprintf("AEGIS-%X-%X", time.Now().Unix(), randomBytes(4))
	chain := fmt.Sprintf("%s:%s:%s:%s:%s", lastHash, caseID, event.IP, ts, event.EventType)
	hash := sha256.Sum256([]byte(chain))
	evidenceHash := fmt.Sprintf("%x", hash[:])

	record := map[string]interface{}{
		"timestamp":          ts,
		"case_id":            caseID,
		"classification":     "LAW_ENFORCEMENT_SENSITIVE",
		"event_type":         event.EventType,
		"ip":                 event.IP,
		"reason":             event.Reason,
		"threat_score":       event.ThreatScore,
		"triad_scores":       event.TriadScores,
		"geo":                event.Geo,
		"tcp_dna":            event.TCPDNA,
		"mitre_attack_ids":   event.MITREAttackIDs,
		"evidence_chain_hash": evidenceHash,
		"previous_hash":      lastHash,
	}

	lastHash = evidenceHash

	data, _ := json.Marshal(record)
	f, err := os.OpenFile(config.EvidenceFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FBI] Write error: %v\n", err)
		return ""
	}
	defer f.Close()
	f.Write(data)
	f.WriteString("\n")

	return caseID
}

func splitLines(s string) []string {
	lines := []string{}
	for _, line := range []byte(s) {
		_ = line
	}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				lines = append(lines, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() & 0xFF)
		time.Sleep(time.Nanosecond)
	}
	return b
}

func GetEvidenceStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total":    0,
		"by_type":  map[string]int{},
		"last_hash": lastHash,
	}

	data, err := os.ReadFile(config.EvidenceFile)
	if err != nil {
		return stats
	}

	lines := splitLines(string(data))
	stats["total"] = len(lines)
	byType := stats["by_type"].(map[string]int)

	for _, line := range lines {
		var rec map[string]interface{}
		if json.Unmarshal([]byte(line), &rec) == nil {
			if t, ok := rec["event_type"].(string); ok {
				byType[t]++
			}
		}
	}
	return stats
}

func EnsureDir() {
	dir := filepath.Dir(config.EvidenceFile)
	os.MkdirAll(dir, 0755)
}
