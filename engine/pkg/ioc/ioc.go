package ioc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

type IOC struct {
	Type        string            `json:"type"`
	Value       string            `json:"value"`
	TLP         string            `json:"tlp"`
	Confidence  float64           `json:"confidence"`
	FirstSeen   string            `json:"first_seen"`
	LastSeen    string            `json:"last_seen"`
	Indicator   string            `json:"indicator"`
	Description string            `json:"description"`
	MitreATTACK []string          `json:"mitre_attack_ids"`
	Context     map[string]string `json:"context"`
	HitCount    int               `json:"hit_count"`
}

type STIXBundle struct {
	Type        string    `json:"type"`
	SpecVersion string    `json:"spec_version"`
	ID          string    `json:"id"`
	Created     string    `json:"created"`
	Modified    string    `json:"modified"`
	Objects     []STIXObj `json:"objects"`
}

type STIXObj struct {
	Type        string   `json:"type"`
	SpecVersion string   `json:"spec_version"`
	ID          string   `json:"id"`
	Created     string   `json:"created"`
	Modified    string   `json:"modified"`
	Name        string   `json:"name,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	PatternType string   `json:"pattern_type,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	ValidFrom   string   `json:"valid_from,omitempty"`
}

var (
	iocCache = map[string]*IOC{}
	iocMu    sync.RWMutex
)

func RecordIOC(iocType, value, description string, confidence float64, mitre []string) {
	iocMu.Lock()
	defer iocMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	if existing, ok := iocCache[value]; ok {
		existing.LastSeen = now
		existing.HitCount++
		return
	}
	iocCache[value] = &IOC{
		Type: iocType, Value: value, TLP: "WHITE", Confidence: confidence,
		FirstSeen: now, LastSeen: now, Indicator: value,
		Description: description, MitreATTACK: mitre,
		Context: map[string]string{"source": "aegis-sigma-shield"},
		HitCount: 1,
	}
	saveIOC(iocCache[value])
}

func GetIOCs() []*IOC {
	iocMu.RLock()
	defer iocMu.RUnlock()
	result := make([]*IOC, 0, len(iocCache))
	for _, ioc := range iocCache {
		result = append(result, ioc)
	}
	return result
}

func GenerateSTIX() *STIXBundle {
	now := time.Now().UTC().Format(time.RFC3339)
	bundle := &STIXBundle{
		Type: "bundle", SpecVersion: "2.1",
		ID: fmt.Sprintf("bundle--%s", generateID()), Created: now, Modified: now,
	}
	iocMu.RLock()
	defer iocMu.RUnlock()
	for _, ioc := range iocCache {
		bundle.Objects = append(bundle.Objects, STIXObj{
			Type: "indicator", SpecVersion: "2.1",
			ID: fmt.Sprintf("indicator--%s", generateID()),
			Created: ioc.FirstSeen, Modified: ioc.LastSeen,
			Name: ioc.Description, Pattern: fmt.Sprintf("[ipv4-addr:value = '%s']", ioc.Value),
			PatternType: "stix", Labels: []string{ioc.Type, "malicious-activity"}, ValidFrom: ioc.FirstSeen,
		})
	}
	return bundle
}

func SaveIOCReport() {
	iocs := GetIOCs()
	data, _ := json.MarshalIndent(iocs, "", "  ")
	os.WriteFile(config.EvidenceDir+"/ioc-report.json", data, 0644)
	stix := GenerateSTIX()
	stixData, _ := json.MarshalIndent(stix, "", "  ")
	os.WriteFile(config.EvidenceDir+"/ioc-stix-bundle.json", stixData, 0644)
}

func generateID() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))[:16]
}

func saveIOC(ioc *IOC) {
	f, err := os.OpenFile(config.EvidenceDir+"/ioc-records.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	data, _ := json.Marshal(ioc)
	f.Write(data)
	f.WriteString("\n")
}
