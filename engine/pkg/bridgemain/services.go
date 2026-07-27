package bridgemain

import (
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Service represents a scraped service from aegis-sigma.com.
type Service struct {
	Name        string `json:"name"`
	Price       string `json:"price"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

var (
	serviceCache   []Service
	serviceCacheMu sync.RWMutex
	serviceCacheAt time.Time
)

// GetServices returns services from cache or scrapes fresh.
func GetServices() []Service {
	serviceCacheMu.RLock()
	if time.Since(serviceCacheAt) < 1*time.Hour && len(serviceCache) > 0 {
		defer serviceCacheMu.RUnlock()
		return serviceCache
	}
	serviceCacheMu.RUnlock()

	services := scrapeServices()
	if len(services) > 0 {
		serviceCacheMu.Lock()
		serviceCache = services
		serviceCacheAt = time.Now()
		serviceCacheMu.Unlock()
	}
	return services
}

// scrapeServices fetches and parses aegis-sigma.com/services.
func scrapeServices() []Service {
	var services []Service

	resp, err := http.Get("https://aegis-sigma.com/services")
	if err != nil {
		log.Printf("[bridge] service scrape failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	html := string(body)

	// Extract service cards: card-name + card-price + features
	// Pattern: <div class="card-name...">NAME</div> ... <div class="card-price...">PRICE</div>
	nameRe := regexp.MustCompile(`class="card-name[^"]*"[^>]*>([^<]+)</div>`)
	priceRe := regexp.MustCompile(`class="card-price[^"]*"[^>]*>\$?([\d,]+)`)
	featureRe := regexp.MustCompile(`(?s)class="card-features"[^>]*>(.*?)</ul>`)
	listItemRe := regexp.MustCompile(`<li[^>]*>(.*?)</li>`)

	names := nameRe.FindAllStringSubmatch(html, -1)
	prices := priceRe.FindAllStringSubmatch(html, -1)
	featureBlocks := featureRe.FindAllStringSubmatch(html, -1)

	for i := 0; i < len(names) && i < len(prices); i++ {
		svc := Service{
			Name:  strings.TrimSpace(names[i][1]),
			Price: "$" + strings.TrimSpace(prices[i][1]),
		}

		// Extract features for this service
		if i < len(featureBlocks) {
			items := listItemRe.FindAllStringSubmatch(featureBlocks[i][1], -1)
			var features []string
			for _, item := range items {
				f := strings.TrimSpace(item[1])
				f = strings.ReplaceAll(f, "&amp;", "&")
				f = strings.ReplaceAll(f, "&#10003;", "✓")
				f = strings.ReplaceAll(f, "&mdash;", "—")
				f = strings.ReplaceAll(f, "&sect;", "§")
				// Clean HTML comments
				if idx := strings.Index(f, "<!--"); idx >= 0 {
					f = strings.TrimSpace(f[:idx])
				}
				// Clean any remaining HTML tags
				f = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(f, "")
				f = strings.TrimSpace(f)
				if f != "" {
					features = append(features, f)
				}
			}
			svc.Description = strings.Join(features, " | ")
		}

		// Categorize
		svc.Category = categorizeService(svc.Name)
		services = append(services, svc)
	}

	// Also extract monthly monitoring tiers
	monthlyRe := regexp.MustCompile(`Subscribe.*?\$(\d+)/mo`)
	monthlyMatches := monthlyRe.FindAllStringSubmatch(html, -1)
	for _, m := range monthlyMatches {
		services = append(services, Service{
			Name:  "Monthly Monitoring",
			Price: "$" + m[1] + "/mo",
			Category: "monitoring",
		})
	}

	log.Printf("[bridge] scraped %d services from aegis-sigma.com", len(services))
	return services
}

// categorizeService maps service names to categories.
func categorizeService(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "audit") || strings.Contains(lower, "scan"):
		return "audit"
	case strings.Contains(lower, "fix") || strings.Contains(lower, "hardening") || strings.Contains(lower, "security"):
		return "security"
	case strings.Contains(lower, "monitor") || strings.Contains(lower, "compliance"):
		return "monitoring"
	case strings.Contains(lower, "removal") || strings.Contains(lower, "mugshot"):
		return "privacy"
	default:
		return "general"
	}
}

// MatchServicesToFindings maps findings to relevant AEGIS-SIGMA services.
func MatchServicesToFindings(findings []Finding, services []Service) []Service {
	var matched []Service
	used := map[string]bool{}

	for _, f := range findings {
		for _, svc := range services {
			key := svc.Name
			if used[key] {
				continue
			}
			if isRelevant(f, svc) {
				matched = append(matched, svc)
				used[key] = true
			}
		}
	}
	return matched
}

// isRelevance checks if a finding is relevant to a service.
func isRelevant(f Finding, svc Service) bool {
	lower := strings.ToLower(svc.Name)
	finding := strings.ToLower(f.Finding)

	switch f.Category {
	case "security":
		return strings.Contains(lower, "security") || strings.Contains(lower, "audit") ||
			strings.Contains(lower, "fix") || strings.Contains(lower, "hardening")
	case "overhaul":
		return strings.Contains(lower, "fix") || strings.Contains(lower, "overhaul") ||
			strings.Contains(lower, "rebuild")
	case "modernization":
		return strings.Contains(lower, "fix") || strings.Contains(lower, "update") ||
			strings.Contains(lower, "modern")
	}

	// Check for specific keyword matches
	if strings.Contains(finding, "dmarc") && strings.Contains(lower, "email") {
		return true
	}
	if strings.Contains(finding, "wordpress") && strings.Contains(lower, "wordpress") {
		return true
	}
	if strings.Contains(finding, "flash") && (strings.Contains(lower, "overhaul") || strings.Contains(lower, "fix")) {
		return true
	}

	return false
}
