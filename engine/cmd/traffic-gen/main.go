// Synthetic benign traffic generator for C engine teacher training.
// Hits your own sites with realistic browser patterns to feed the teacher
// real "benign" classifications. Runs for a configurable duration then exits.
// Designed for cron on ARM: every 30 min during business hours.
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// --- Config ---

type Config struct {
	Targets   []Target `json:"targets"`
	Duration  string   `json:"duration"`
	MaxVisits int      `json:"max_visits"`
}

type Target struct {
	URL   string   `json:"url"`   // base URL, e.g. "https://aegis-sigma.com"
	Paths []string `json:"paths"` // paths to visit
}

// --- User Agent Pool ---

var userAgents = []string{
	// Chrome on various OS
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	// Firefox
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
	// Safari
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	// Edge
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	// Mobile
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
}

// --- Referer Pool ---

var referers = []string{
	"", // direct (30% of visits)
	"", // direct
	"",
	"https://www.google.com/search?q=ciberseguridad+empresarial",
	"https://www.google.com/search?q=security+audit+services",
	"https://www.google.com/search?q=website+security+scan",
	"https://www.google.com/search?q=ciberseguridad+near+me",
	"https://www.google.com/search?q=small+business+security",
	"https://www.bing.com/search?q=security+services",
	"https://www.bing.com/search?q=cybersecurity+consulting",
	"https://duckduckgo.com/?q=website+vulnerability+scan",
	"https://www.facebook.com/",
	"https://www.linkedin.com/feed/",
	"https://twitter.com/home",
}

// --- Visitor Sessions ---

type session struct {
	ua      string
	referer string
	pages   int // how many pages this visitor browses
}

func newSession() session {
	ua := userAgents[randInt(len(userAgents))]
	ref := referers[randInt(len(referers))]
	// Real visitors browse 1-6 pages per session
	pages := 1 + randInt(5)
	return session{ua: ua, referer: ref, pages: pages}
}

func (s session) visit(client *http.Client, target Target, delay time.Duration, logf func(string)) {
	visited := 0
	var currentReferer string

	for i := 0; i < s.pages; i++ {
		path := target.Paths[randInt(len(target.Paths))]
		url := strings.TrimRight(target.URL, "/") + path

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			logf(fmt.Sprintf("[ERR] %v", err))
			return
		}
		req.Header.Set("User-Agent", s.ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,es;q=0.8")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")

		// Set referer — first page uses session referer, subsequent use previous page
		if i == 0 && s.referer != "" {
			req.Header.Set("Referer", s.referer)
			currentReferer = s.referer
		} else if currentReferer != "" {
			req.Header.Set("Referer", currentReferer)
		}

		resp, err := client.Do(req)
		if err != nil {
			logf(fmt.Sprintf("[ERR] %s %s: %v", s.ua[:20], url, err))
			return
		}
		resp.Body.Close()
		logf(fmt.Sprintf("[VISIT] %d %s %s (referer=%s)", resp.StatusCode, s.ua[:25], path, truncateRef(currentReferer)))

		currentReferer = url
		visited++

		// Random delay between pages: 2-15 seconds (natural browsing)
		if i < s.pages-1 {
			wait := 2 + randInt(13)
			time.Sleep(time.Duration(wait) * time.Second)
		}
	}

	_ = visited
}

// --- Main ---

func main() {
	configPath := flag.String("config", "/etc/aegis-sigma/traffic-gen.json", "config file path")
	duration := flag.Duration("duration", 0, "override duration (e.g. 30m)")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	// Default config
	cfg := Config{
		Duration:  "30m",
		MaxVisits: 200,
		Targets: []Target{},
	}

	// Load config if exists
	if data, err := os.ReadFile(*configPath); err == nil {
		json.Unmarshal(data, &cfg)
	}

	// If no targets configured, auto-discover from env vars
	if len(cfg.Targets) == 0 {
		if v := os.Getenv("PRIMARY_SITE"); v != "" {
			cfg.Targets = append(cfg.Targets, Target{URL: v})
		}
		if v := os.Getenv("SECONDARY_SITE"); v != "" {
			cfg.Targets = append(cfg.Targets, Target{URL: v})
		}
	}

	// Wildcard paths — probe common paths on every site
	wildcardPaths := []string{
		"/", "/about", "/services", "/contact", "/pricing",
		"/blog", "/docs", "/support", "/login", "/features",
	}
	for i := range cfg.Targets {
		if len(cfg.Targets[i].Paths) == 0 {
			cfg.Targets[i].Paths = wildcardPaths
		}
	}

	// Override duration from flag
	if *duration > 0 {
		cfg.Duration = (*duration).String()
	}

	dur, err := time.ParseDuration(cfg.Duration)
	if err != nil {
		dur = 30 * time.Minute
	}

	logf := func(msg string) {
		fmt.Printf("[traffic-gen] %s %s\n", time.Now().Format("15:04:05"), msg)
	}
	if !*verbose {
		logf = func(msg string) {
			if strings.HasPrefix(msg, "[VISIT]") || strings.HasPrefix(msg, "[ERR]") || strings.HasPrefix(msg, "[SESSION]") {
				fmt.Printf("[traffic-gen] %s %s\n", time.Now().Format("15:04:05"), msg)
			}
		}
	}

	logf(fmt.Sprintf("Starting synthetic traffic generator (duration=%s, max_visits=%d)", dur, cfg.MaxVisits))

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	deadline := time.Now().Add(dur)
	totalVisits := 0
	var mu sync.Mutex

	for time.Now().Before(deadline) && totalVisits < cfg.MaxVisits {
		// Pick a random target
		target := cfg.Targets[randInt(len(cfg.Targets))]

		// Create a visitor session
		sess := newSession()
		logf(fmt.Sprintf("[SESSION] new visitor: %s pages=%d referer=%s", sess.ua[:30], sess.pages, truncateRef(sess.referer)))

		// Visit the target
		sess.visit(client, target, 0, logf)

		mu.Lock()
		totalVisits++
		mu.Unlock()

		// Delay between visitors: 5-45 seconds (simulates organic arrival)
		gap := 5 + randInt(40)
		time.Sleep(time.Duration(gap) * time.Second)
	}

	logf(fmt.Sprintf("Done: %d total visits across %d targets", totalVisits, len(cfg.Targets)))
}

func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	val, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(val.Int64())
}

func truncateRef(s string) string {
	if s == "" {
		return "direct"
	}
	if idx := strings.Index(s, "//"); idx >= 0 {
		s = s[idx+2:]
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
