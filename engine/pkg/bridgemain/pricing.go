package bridgemain

import (
	"fmt"
	"strings"
)

// PriceItem represents a line item in a quote.
type PriceItem struct {
	Service     string `json:"service"`
	Description string `json:"description"`
	Price       int    `json:"price"` // cents
	Category    string `json:"category"`
}

// Quote represents a full quote with line items and total.
type Quote struct {
	Domain      string      `json:"domain"`
	Email       string      `json:"email"`
	BusinessName string     `json:"business_name"`
	Items       []PriceItem `json:"items"`
	Total       int         `json:"total"` // cents
	Summary     string      `json:"summary"`
}

// GeneratePricing maps scan findings to suggested retail prices.
// Returns a Quote with line items, descriptions, and a total.
func GeneratePricing(report Report, email string) Quote {
	quote := Quote{
		Domain:       report.Domain,
		Email:        email,
		BusinessName: report.BusinessName,
		Items:        []PriceItem{},
	}

	// Track which services we've already added (avoid duplicates)
	added := map[string]bool{}

	for _, f := range report.Findings {
		items := priceFinding(f)
		for _, item := range items {
			key := strings.ToLower(item.Service)
			if !added[key] {
				added[key] = true
				quote.Items = append(quote.Items, item)
				quote.Total += item.Price
			}
		}
	}

	// If no findings, offer a basic audit
	if len(quote.Items) == 0 {
		quote.Items = append(quote.Items, PriceItem{
			Service:     "Security Audit",
			Description: "Full perimeter scan, SWOT report, and remediation roadmap",
			Price:       49900,
			Category:    "audit",
		})
		quote.Total = 49900
	}

	quote.Summary = buildQuoteSummary(quote)
	return quote
}

// priceFinding maps a single finding to one or more price items.
func priceFinding(f Finding) []PriceItem {
	var items []PriceItem

	switch {
	// Security findings
	case strings.Contains(strings.ToLower(f.Finding), "csp") || strings.Contains(strings.ToLower(f.Finding), "content-security-policy"):
		items = append(items, PriceItem{
			Service:     "Content-Security-Policy Setup",
			Description: "Configure CSP headers to prevent XSS and data injection attacks",
			Price:       25000, // $250
			Category:    "security",
		})
	case strings.Contains(strings.ToLower(f.Finding), "hsts"):
		items = append(items, PriceItem{
			Service:     "HSTS Configuration",
			Description: "Enable HTTP Strict Transport Security to prevent downgrade attacks",
			Price:       15000, // $150
			Category:    "security",
		})
	case strings.Contains(strings.ToLower(f.Finding), "x-frame-options") || strings.Contains(strings.ToLower(f.Finding), "clickjacking"):
		items = append(items, PriceItem{
			Service:     "Clickjacking Protection",
			Description: "Add X-Frame-Options header to prevent clickjacking attacks",
			Price:       15000, // $150
			Category:    "security",
		})
	case strings.Contains(strings.ToLower(f.Finding), "x-content-type"):
		items = append(items, PriceItem{
			Service:     "MIME Type Protection",
			Description: "Add X-Content-Type-Options header to prevent MIME sniffing",
			Price:       10000, // $100
			Category:    "security",
		})
	case strings.Contains(strings.ToLower(f.Finding), "dmarc") || strings.Contains(strings.ToLower(f.Finding), "email spoof"):
		items = append(items, PriceItem{
			Service:     "DMARC Policy Setup",
			Description: "Configure DMARC to prevent email spoofing and phishing attacks",
			Price:       40000, // $400
			Category:    "security",
		})
	case strings.Contains(strings.ToLower(f.Finding), "dnssec"):
		items = append(items, PriceItem{
			Service:     "DNSSEC Enablement",
			Description: "Enable DNSSEC to prevent DNS spoofing and cache poisoning",
			Price:       25000, // $250
			Category:    "security",
		})
	case strings.Contains(strings.ToLower(f.Finding), "http only") || strings.Contains(strings.ToLower(f.Finding), "no tls"):
		items = append(items, PriceItem{
			Service:     "TLS/SSL Setup",
			Description: "Install and configure SSL certificate, redirect HTTP to HTTPS",
			Price:       35000, // $350
			Category:    "security",
		})
	case strings.Contains(strings.ToLower(f.Finding), "mixed content"):
		items = append(items, PriceItem{
			Service:     "Mixed Content Cleanup",
			Description: "Fix HTTP resources loaded on HTTPS pages, update internal links",
			Price:       40000, // $400
			Category:    "security",
		})

	// Overhaul findings
	case strings.Contains(strings.ToLower(f.Finding), "flash") || strings.Contains(strings.ToLower(f.Finding), "dead technology"):
		items = append(items, PriceItem{
			Service:     "Flash Removal & Replacement",
			Description: "Remove Flash content and replace with modern HTML5/JavaScript alternatives",
			Price:       100000, // $1,000
			Category:    "overhaul",
		})
	case strings.Contains(f.Finding, "table-based layout") || strings.Contains(f.Finding, "responsive"):
		items = append(items, PriceItem{
			Service:     "Responsive Redesign",
			Description: "Redesign site layout for mobile, tablet, and desktop compatibility",
			Price:       180000, // $1,800
			Category:    "overhaul",
		})
	case strings.Contains(f.Finding, "HTML4") || strings.Contains(f.Finding, "outdated doctype"):
		items = append(items, PriceItem{
			Service:     "HTML5 Modernization",
			Description: "Update doctype, semantic HTML, and modern web standards",
			Price:       120000, // $1,200
			Category:    "overhaul",
		})
	case strings.Contains(f.Finding, "viewport"):
		items = append(items, PriceItem{
			Service:     "Mobile Responsiveness",
			Description: "Add viewport meta tag and responsive design adjustments",
			Price:       60000, // $600
			Category:    "overhaul",
		})

	// Modernization findings
	case strings.Contains(f.Finding, "jQuery") && strings.Contains(f.Finding, "outdated"):
		items = append(items, PriceItem{
			Service:     "jQuery Update",
			Description: "Update jQuery to latest stable version, fix compatibility issues",
			Price:       35000, // $350
			Category:    "modernization",
		})
	case strings.Contains(f.Finding, "WordPress") && strings.Contains(f.Finding, "outdated"):
		items = append(items, PriceItem{
			Service:     "WordPress Update & Hardening",
			Description: "Update WordPress core, plugins, and apply security hardening",
			Price:       50000, // $500
			Category:    "modernization",
		})
	case strings.Contains(f.Finding, "WordPress") && !strings.Contains(f.Finding, "outdated"):
		items = append(items, PriceItem{
			Service:     "WordPress Security Audit",
			Description: "Review WordPress configuration and apply security best practices",
			Price:       25000, // $250
			Category:    "modernization",
		})

	// Exposure findings
	case strings.Contains(f.Finding, "admin path") || strings.Contains(f.Finding, "exposed"):
		items = append(items, PriceItem{
			Service:     "Exposed Path Remediation",
			Description: "Remove or restrict access to exposed admin paths and sensitive files",
			Price:       30000, // $300
			Category:    "security",
		})

	// Email security findings
	case strings.Contains(f.Finding, "SPF") || strings.Contains(f.Finding, "DKIM"):
		items = append(items, PriceItem{
			Service:     "Email Authentication Setup",
			Description: "Configure SPF and DKIM records for email deliverability and security",
			Price:       30000, // $300
			Category:    "security",
		})
	}

	return items
}

// buildQuoteSummary generates a human-readable summary of the quote.
func buildQuoteSummary(q Quote) string {
	if len(q.Items) == 0 {
		return "No immediate fixes required. We recommend a security audit to identify potential issues."
	}
	var parts []string
	for _, item := range q.Items {
		parts = append(parts, fmt.Sprintf("%s ($%d)", item.Service, item.Price/100))
	}
	return fmt.Sprintf("Recommended services for %s: %s. Total: $%d.",
		q.Domain, strings.Join(parts, ", "), q.Total/100)
}

// FormatPrice formats cents as a dollar string.
func FormatPrice(cents int) string {
	return fmt.Sprintf("$%d", cents/100)
}
