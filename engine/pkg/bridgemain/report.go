package bridgemain

import (
	"fmt"
	"sort"
	"strings"
)

// Finding represents a parsed scan finding from the lead's notes field.
type Finding struct {
	Category string `json:"category"` // security, overhaul, modernization, exposure, email
	Severity int    `json:"severity"` // 1-10 (10 = critical)
	Finding  string `json:"finding"`  // human-readable description
	Priority int    `json:"priority"` // computed: severity * category weight
}

// Report represents a full scan report for a lead.
type Report struct {
	Domain        string
	Email         string
	BusinessName  string
	City          string
	State         string
	BusinessType  string
	Score         int
	Findings      []Finding
	SecurityCount int
	OverhaulCount int
	ModernCount   int
	RiskLevel     string // Critical, High, Medium, Low
}

// ParseFindings extracts structured findings from the lead's notes field.
// Format: [category/severity] finding text | [category/severity] finding text
// Also handles contact info: phone: +1-xxx-xxx-xxxx | address: xxx Street, City, ST ZIP
func ParseFindings(notes string) []Finding {
	var findings []Finding
	if notes == "" {
		return findings
	}

	// Split on pipe separator or newlines
	parts := strings.FieldsFunc(notes, func(r rune) bool {
		return r == '|' || r == '\n'
	})

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Try to parse [category/severity] format
		if strings.HasPrefix(part, "[") && strings.Contains(part, "/") {
			endBracket := strings.Index(part, "]")
			if endBracket > 0 {
				inner := part[1:endBracket]
				parts2 := strings.SplitN(inner, "/", 2)
				if len(parts2) == 2 {
					cat := strings.ToLower(strings.TrimSpace(parts2[0]))
					var sev int
					fmt.Sscanf(strings.TrimSpace(parts2[1]), "%d", &sev)
					finding := strings.TrimSpace(part[endBracket+1:])
					if finding != "" {
						findings = append(findings, Finding{
							Category: cat,
							Severity: sev,
							Finding:  finding,
							Priority: computePriority(cat, sev),
						})
					}
					continue
				}
			}
		}
		if strings.HasPrefix(part, "[scan]") {
			// Simple scan result — may contain nested [category/severity] findings
			remainder := strings.TrimSpace(strings.TrimPrefix(part, "[scan]"))
			if remainder == "" || remainder == "clean — no issues detected" {
				continue
			}
			// Check if remainder contains [category/severity] format
			if strings.HasPrefix(remainder, "[") && strings.Contains(remainder, "/") {
				endBracket := strings.Index(remainder, "]")
				if endBracket > 0 {
					inner := remainder[1:endBracket]
					parts2 := strings.SplitN(inner, "/", 2)
					if len(parts2) == 2 {
						cat := strings.ToLower(strings.TrimSpace(parts2[0]))
						var sev int
						fmt.Sscanf(strings.TrimSpace(parts2[1]), "%d", &sev)
						finding := strings.TrimSpace(remainder[endBracket+1:])
						if finding != "" {
							findings = append(findings, Finding{
								Category: cat,
								Severity: sev,
								Finding:  finding,
								Priority: computePriority(cat, sev),
							})
						}
					}
				}
			} else {
				findings = append(findings, Finding{
					Category: "general",
					Severity: 3,
					Finding:  remainder,
					Priority: 3,
				})
			}
		} else if strings.HasPrefix(part, "phone:") || strings.HasPrefix(part, "address:") {
			// Contact info findings
			finding := strings.TrimSpace(part)
			if finding != "" {
				findings = append(findings, Finding{
					Category: "contact",
					Severity: 0,
					Finding:  finding,
					Priority: 0,
				})
			}
		}
	}

	// Sort by priority (highest first)
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Priority > findings[j].Priority
	})

	return findings
}

// computePriority weights findings by category and severity.
// Security issues are highest priority, then overhaul, then modernization.
func computePriority(category string, severity int) int {
	weight := 1
	switch category {
	case "security":
		weight = 3
	case "overhaul":
		weight = 2
	case "exposure":
		weight = 2
	case "modernization":
		weight = 1
	case "email":
		weight = 2
	}
	return severity * weight
}

// BuildReport constructs a Report from lead data and parsed findings.
func BuildReport(domain, name, city, state, bizType string, score int, notes string) Report {
	findings := ParseFindings(notes)
	report := Report{
		Domain:       domain,
		BusinessName: name,
		City:         city,
		State:        state,
		BusinessType: bizType,
		Score:        score,
		Findings:     findings,
	}

	for _, f := range findings {
		switch f.Category {
		case "security":
			report.SecurityCount++
		case "overhaul":
			report.OverhaulCount++
		case "modernization", "modern":
			report.ModernCount++
		}
	}

	// Determine risk level based on findings severity, not capped score
	maxSeverity := 0
	for _, f := range findings {
		if f.Severity > maxSeverity {
			maxSeverity = f.Severity
		}
	}
	switch {
	case maxSeverity >= 8:
		report.RiskLevel = "Critical"
	case maxSeverity >= 5:
		report.RiskLevel = "High"
	case maxSeverity >= 3:
		report.RiskLevel = "Medium"
	default:
		report.RiskLevel = "Low"
	}

	return report
}

// Summary generates a one-paragraph summary for emails.
func (r Report) Summary() string {
	// No findings means scan hasn't run yet. Don't pitch a $499 scan for nothing.
	if len(r.Findings) == 0 {
		return fmt.Sprintf("Scan not yet run on %s — click Rescan to audit this site for security, structural, and modernization issues.", r.Domain)
	}
	var parts []string
	if r.SecurityCount > 0 {
		parts = append(parts, fmt.Sprintf("%d security issue(s)", r.SecurityCount))
	}
	if r.OverhaulCount > 0 {
		parts = append(parts, fmt.Sprintf("%d structural issue(s)", r.OverhaulCount))
	}
	if r.ModernCount > 0 {
		parts = append(parts, fmt.Sprintf("%d modernization item(s)", r.ModernCount))
	}
	return fmt.Sprintf("Our assessment of %s identified %s. Overall risk level: %s (score: %d/100).",
		r.Domain, strings.Join(parts, ", "), r.RiskLevel, r.Score)
}
