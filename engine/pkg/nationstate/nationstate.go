package nationstate

import (
	"encoding/json"
	"strings"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Attribution is a heuristic nation-state attribution call.
// Returns a label like "Russia", "China", "Iran", "North Korea" or "Unknown".

// Known hostile ASN/org substrings that have appeared in real incident DBs.
var knownASNs = map[string]string{
	"AS14061":          "China",
	"AS4134":           "China",
	"AS4837":           "China",
	"AS9808":           "China",
	"AS4812":           "China",
	"AS17676":          "China",
	"AS3216":           "Russia",
	"AS9002":           "Russia",
	"AS12389":          "Russia",
	"AS20485":          "Russia",
	"AS28917":          "Russia",
	"AS49505":          "Russia",
	"AS29073":          "Russia",
	"AS39736":          "Russia",
	"AS44592":          "Iran",
	"AS49666":          "Iran",
	"AS44208":          "Iran",
	"AS48754":          "Iran",
	"AS131277":         "North Korea",
	"AS131279":         "North Korea",
	"AS13443":          "North Korea",
}

// Known hostile country codes.
var knownCountries = map[string]string{
	"RU": "Russia", "CN": "China", "IR": "Iran", "KP": "North Korea",
	"BY": "Russia", "TR": "Turkey", "BR": "Brazil (cybercrime hub)",
	"NL": "EU Anonymizer Hub", "DE": "EU Anonymizer Hub",
}

// Known hostile ASN org name substrings (lowercase checks).
var orgSubstrings = map[string]string{
	"selectel":      "Russia",
	"OVH":           "EU Anonymizer Hub",
	"hetzner":       "EU Anonymizer Hub",
	"contabo":       "EU Anonymizer Hub",
	"choopa":        "VPN/Proxy",
	"m247":          "VPN/Proxy",
	"surfshark":     "VPN/Proxy",
	"nordvpn":       "VPN/Proxy",
	"vpn":           "VPN/Proxy",
	"tor exit":      "TOR Exit Node",
	"tor":           "TOR Exit Node",
}

// AttributeFast is a pure heuristic that never opens a DB connection.
// Use in hot paths (backfill, batch operations) to avoid WAL lock contention.
func AttributeFast(asn, country, isp, org string) string {
	if asn != "" {
		if n, ok := knownASNs[strings.ToUpper(asn)]; ok {
			return n
		}
	}
	if country != "" {
		if n, ok := knownCountries[strings.ToUpper(country)]; ok {
			return n
		}
	}
	combined := strings.ToLower(isp + " " + org)
	for fragment, n := range orgSubstrings {
		if strings.Contains(combined, strings.ToLower(fragment)) {
			return n
		}
	}
	return "Unknown"
}

// Attribute returns the best nation-state attribution call based on ASN,
// country, and org/ISP text. Returns "Unknown" if nothing matches.
func Attribute(asn, country, isp, org string) string {
	if asn != "" {
		if n, ok := knownASNs[strings.ToUpper(asn)]; ok {
			return n
		}
	}
	if country != "" {
		if n, ok := knownCountries[strings.ToUpper(country)]; ok {
			return n
		}
	}
	combined := strings.ToLower(isp + " " + org)
	for fragment, n := range orgSubstrings {
		if strings.Contains(combined, strings.ToLower(fragment)) {
			return n
		}
	}
	// IP-based lookup as last resort — short-circuit to database identities if present
	if country == "" || asn == "" {
		// Some enrichment_results may have stored attribution indirectly
		if n := lookupFromEnrichment(asn, country); n != "" {
			return n
		}
	}
	return "Unknown"
}

func lookupFromEnrichment(asn, ip string) string {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return ""
	}
	defer d.Close()
	var result string
	d.QueryRow("SELECT result FROM enrichment_results WHERE ip = ? ORDER BY id DESC LIMIT 1", ip).Scan(&result)
	if result == "" {
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal([]byte(result), &m) != nil {
		return ""
	}
	if cc, ok := m["country_code"].(string); ok {
		if n, ok := knownCountries[cc]; ok {
			return n
		}
	}
	return ""
}

// ListKnown returns the static known ASN map for inlining in dashboards.
func ListKnown() map[string]string {
	out := map[string]string{}
	for k, v := range knownASNs {
		out[k] = v
	}
	return out
}
