package federal

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
	"github.com/aegis-sigma/engine/pkg/nationstate"
)

// Case describes the federal mapping derived from an attack's TTPs — a SAR
// (Suspicious Activity Report) code + an FBI narrative label + MITRE IDs.

type Case struct {
	SARCode    string   `json:"sar_code"`
	FBILabel   string   `json:"fbi_label"`
	MITREIDs   []string `json:"mitre_ids"`
	FederalID  string   `json:"federal_id"`  // persisted to forensic_reports.federal_mapping
	Nation     string   `json:"nation_state_attribution"`
}

// MapFromPath derives a federal case mapping from a request URI / reason.
// Returns a best-effort Case — if nothing matches, falls back to the default
// "scanner" mapping (config.FederalCodes["default"]).
func MapFromPath(uri, reason string) Case {
	key := classifyPath(uri, reason)
	entry, ok := config.FederalCodes[key]
	if !ok {
		entry = config.FederalCodes["default"]
	}
	sar, _ := entry["sar"].(string)
	fbi, _ := entry["fbi"].(string)
	mitre, _ := entry["mitre"].([]string)
	return Case{
		SARCode:   sar,
		FBILabel:  fbi,
		MITREIDs:  asStrings(mitre),
		FederalID: federalID(sar, fbi),
	}
}

// WriteToForensic persists the Federal Case mapping back onto the matching
// forensic_reports rows by IP + recent created_at. Also writes
// nation_state_attribution if provided (caller sets on the Case).
func WriteToForensic(ip string, fc Case) {
	if ip == "" || fc.FederalID == "" {
		return
	}
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	mapping, _ := json.Marshal(fc)
	_, _ = d.Exec(`UPDATE forensic_reports SET
		federal_mapping = ?, nation_state_attribution = ?
		WHERE ip = ? AND (federal_mapping IS NULL OR federal_mapping = '')`,
		string(mapping), fc.Nation, ip)
}

// ListCases returns cases grouped by SAR code for the dashboard.
func ListCases(limit int) []map[string]interface{} {
	if limit <= 0 {
		limit = 100
	}
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT ip, federal_mapping, nation_state_attribution, created_at
		FROM forensic_reports
		WHERE federal_mapping IS NOT NULL AND federal_mapping != ''
		ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var ip, mapping, nation, ts string
		rows.Scan(&ip, &mapping, &nation, &ts)
		var fc Case
		if json.Unmarshal([]byte(mapping), &fc) == nil {
			out = append(out, map[string]interface{}{
				"ip":          ip,
				"sar_code":    fc.SARCode,
				"fbi_label":   fc.FBILabel,
				"mitre_ids":   fc.MITREIDs,
				"federal_id":  fc.FederalID,
				"nation":      fc.Nation,
				"created_at":  ts,
			})
		}
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}

func classifyPath(uri, reason string) string {
	p := strings.ToLower(uri)
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(p, "xmlrpc"):
		return "xmlrpc"
	case strings.Contains(p, ".git"):
		return "git"
	case strings.Contains(p, "wp-admin"), strings.Contains(p, "wp-login"):
		return "wp-admin"
	case strings.HasPrefix(r, "tor"), strings.Contains(p, "tor"):
		return "tor"
	case strings.Contains(p, ".aws"), strings.Contains(p, "credentials"):
		return "aws"
	case strings.Contains(p, ".env"):
		return "env"
	case strings.Contains(p, "phpinfo"):
		return "phpinfo"
	case strings.Contains(p, "login"):
		return "login"
	default:
		return "default"
	}
}

func federalID(sar, fbi string) string {
	// Compact, deterministic federal case ID: SAR-FBI-sha-prefix
	return "FED-" + sar + "-" + time.Now().UTC().Format("20060102")
}

func asStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// BackfillAll re-processes all forensic_reports with empty federal_mapping and
// nation_state_attribution. Called once on deployment to backfill old rows.
// Returns the count of rows updated. Uses a single DB connection and skips
// enrichment_results lookups to avoid WAL lock contention.
func BackfillAll() int {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0
	}
	defer d.Close()

	// Step 1: update federal_mapping on all empty rows
	_, _ = d.Exec(`UPDATE forensic_reports SET federal_mapping = '' WHERE federal_mapping IS NULL`)

	rows, err := d.Query(`SELECT id, ip, request_uri, reason, country, isp_asn
		FROM forensic_reports WHERE federal_mapping = '' OR federal_mapping IS NULL
		ORDER BY id ASC`)
	if err != nil {
		return 0
	}

	updated := 0
	type row struct {
		id             int
		ip, uri, reason, country, asn string
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ip, &r.uri, &r.reason, &r.country, &r.asn); err != nil {
			continue
		}
		batch = append(batch, r)
	}
	rows.Close()

	// Step 2: update each row — no DB call inside nationstate.Attribute
	// (we pass the country/asn directly from the row, skip enrichment lookup)
	for _, r := range batch {
		fc := MapFromPath(r.uri, r.reason)
		fc.Nation = nationstate.AttributeFast(r.asn, r.country, "", "")
		mappingJSON, _ := json.Marshal(fc)
		_, err := d.Exec(`UPDATE forensic_reports
			SET federal_mapping = ?, nation_state_attribution = ?
			WHERE id = ?`,
			string(mappingJSON), fc.Nation, r.id)
		if err == nil {
			updated++
		}
	}
	return updated
}
