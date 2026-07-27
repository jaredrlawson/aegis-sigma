package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/internal/types"
	"github.com/aegis-sigma/engine/pkg/abuse"
	"github.com/aegis-sigma/engine/pkg/auditor"
	"github.com/aegis-sigma/engine/pkg/blockledger"
	"github.com/aegis-sigma/engine/pkg/cadence"
	"github.com/aegis-sigma/engine/pkg/cengine"
	"github.com/aegis-sigma/engine/pkg/coherence"
	"github.com/aegis-sigma/engine/pkg/db"
	"github.com/aegis-sigma/engine/pkg/enrichment"
	"github.com/aegis-sigma/engine/pkg/extractor"
	"github.com/aegis-sigma/engine/pkg/fbi"
	"github.com/aegis-sigma/engine/pkg/federal"
	"github.com/aegis-sigma/engine/pkg/identity"
	"github.com/aegis-sigma/engine/pkg/ioc"
	"github.com/aegis-sigma/engine/pkg/lattice"
	"github.com/aegis-sigma/engine/pkg/nationstate"
	"github.com/aegis-sigma/engine/pkg/pages"
	"github.com/aegis-sigma/engine/pkg/pow"
	"github.com/aegis-sigma/engine/pkg/profiler"
	"github.com/aegis-sigma/engine/pkg/selfhealer"
	"github.com/aegis-sigma/engine/pkg/synaptic"
	"github.com/aegis-sigma/engine/pkg/threatfeed"
	"github.com/aegis-sigma/engine/pkg/trapledger"
	"github.com/aegis-sigma/engine/pkg/triadclient"
	"github.com/aegis-sigma/engine/pkg/voidpunisher"
)

const SHIELD_LOG = "/var/log/aegis/shield_soul.log"

// nowStamp returns an ISO-8601 timestamp with the local tz offset baked in.
// Self-healing per-install: whatever timezone the box is set to (UTC, EDT,
// PST, etc.) is what lands in the string. JS `new Date(...)` reads the
// offset and renders in the visitor's browser tz. No hardcoded tz here —
// the customer's box dictates the offset.
func nowStamp() string {
	return time.Now().Format("2006-01-02T15:04:05.000-07:00")
}

func appendShieldLog(msg string) {
	f, err := os.OpenFile(SHIELD_LOG, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	f.WriteString(fmt.Sprintf("[%s] %s\n", ts, msg))
}

var challengeRegexp = regexp.MustCompile(`aegis_challenge=([^;]+)`)

func main() {
	// Telemetry is mandatory — system refuses to start without it
	if os.Getenv("TELEMETRY_URL") == "" {
		fmt.Println("[SHIELD] ERROR: TELEMETRY_URL not configured.")
		fmt.Println("[SHIELD] Set TELEMETRY_URL in .env or run ./scripts/setup.sh")
		fmt.Println("[SHIELD] Telemetry is required for AEGIS-SIGMA Community Edition.")
		os.Exit(1)
	}

	os.MkdirAll(config.EvidenceDir, 0755)
	fbi.Init()
	loadConfigEnv()
	config.StartRouteCache()
	go selfhealer.Start()
	go threatfeed.FanOut()
	go func() {
		for {
			checkTelemetryHeartbeat()
			time.Sleep(5 * time.Minute)
		}
	}()

	http.HandleFunc("/", handleRequest)
	http.HandleFunc("/test-bot-connection", handleHealth)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/challenge-page", handleChallengePage)
	http.HandleFunc("/challenge-verify", handleChallengeVerify)
	http.HandleFunc("/_aegis_auth", handleAegisAuth)
	http.HandleFunc("/pow/challenge", handlePowChallenge)
	http.HandleFunc("/pow/verify", handlePowVerify)
	http.HandleFunc("/api/v1/register-site", handleRegisterSite)
	http.HandleFunc("/robots.txt", handleRobots)
	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/threat-feed", threatfeed.HandleWebSocket)
	http.HandleFunc("/api/profiler/stats", handleProfilerStats)
	http.HandleFunc("/api/ioc/report", handleIOCReport)
	http.HandleFunc("/api/abuse/stats", handleAbuseStats)
	http.HandleFunc("/forensic-attribution", handleForensicAttribution)
	http.HandleFunc("/api/strike/event", handleStrikeEvent)
	http.HandleFunc("/api/groq-teacher", handleGroqTeacher)
	http.HandleFunc("/t/", handleTracker)
	http.HandleFunc("/api/tracker/ingest", handleTrackerIngest)

	fmt.Printf("[SHIELD] Go shield v5.0 on :%d\n", config.ShieldPort)
	fmt.Printf("[SHIELD] C engine: %s:%d\n", config.CEngineHost, config.CEnginePort)
	fmt.Printf("[SHIELD] GEOIP: %s\n", config.GeoIPURL)
	fmt.Printf("[SHIELD] Strike: %s\n", config.StrikeURL)
	fmt.Printf("[SHIELD] Brain: %s\n", config.BrainDB)
	fmt.Printf("[SHIELD] Modules: enrichment, triadclient, voidpunisher, fbi, pages, profiler, ioc, abuse, threatfeed, selfhealer\n")
	http.ListenAndServe(fmt.Sprintf(":%d", config.ShieldPort), nil)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	// protect against public exposure
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !strings.HasPrefix(addr, "127.") && !strings.HasPrefix(addr, "::1") && !strings.HasPrefix(addr, "10.88.0.") {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`))
		return
	}
	if token := r.Header.Get("X-Health-Token"); token != "" && token != config.HealthToken {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "agent": "v5.0", "version": "5.0.0"})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	// protect status endpoint
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !strings.HasPrefix(addr, "127.") && !strings.HasPrefix(addr, "::1") && !strings.HasPrefix(addr, "10.88.0.") {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`))
		return
	}
	if token := r.Header.Get("X-Health-Token"); token != "" && token != config.HealthToken {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	stats := getStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("User-agent: *\nDisallow: /api/\nDisallow: /kernel/\n"))
}

func handleChallengePage(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	ua := r.UserAgent()
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	html := pages.ChallengePage(ip, ua, redirect, config.StrikeURL)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(403)
	w.Write([]byte(html))
}

func handleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", 302)
		return
	}
	r.ParseForm()
	userAnswer := r.FormValue("user_answer")
	ip := getClientIP(r)
	ua := r.UserAgent()
	if userAnswer == "" {
		html := pages.ChallengePage(ip, ua, "/", config.StrikeURL)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		w.Write([]byte(html))
		return
	}
	cookie := pages.GenerateSlidingCookie(ip, ua)
	http.SetCookie(w, &http.Cookie{
		Name: "aegis_challenge", Value: cookie, Path: "/",
		MaxAge: 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", 302)
}

// handleAegisAuth is the auth_request subrequest handler invoked by nginx for
// every page load. It does ONE thing: validate the aegis_challenge cookie.
//   200 → nginx proxies the request through to the landing backend.
//   403 → nginx intercepts (error_page 403 = @aegis_challenge) and 302s the
//         browser to /challenge-page?redirect=<original-URI>; the browser
//         solves the PoW, gets the cookie, and retries — at which point this
//         handler returns 200 and traffic flows.
// No side effects, no DB writes, no redirects issued from here. Designed to be
// horizontally scalable: any Shield replica can answer any subrequest.
// ponytail: fail-closed is the default; nginx snippet overrides with error_page
// to fail-open if Shield returns 5xx (avoids a global blackout on outage).
func handleAegisAuth(w http.ResponseWriter, r *http.Request) {
	ip := normalizeIP(getClientIP(r))
	ua := r.UserAgent()
	cookieHeader := r.Header.Get("Cookie")
	match := challengeRegexp.FindStringSubmatch(cookieHeader)
	if pages.ValidateChallengeCookie(getString(match, 1), ua, ip) {
		w.WriteHeader(200)
		return
	}
	w.WriteHeader(403)
}

// handlePowChallenge issues a PoW challenge to the browser. Difficulty is
// derived from the IP's strike count — more strikes = harder puzzle.
func handlePowChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		ip = getClientIP(r)
	}
	rawIP := normalizeIP(ip)
	strikes := profiler.GetStrikeCount(rawIP)
	// Difficulty = hex zeros in the hash prefix. Each hex zero = 4 bits.
	// 4 hex zeros = 16 bits = ~65K hashes = ~2-4s on phone (sweet spot).
	// 5 hex zeros = 20 bits = ~1M hashes = ~30s on phone (repeat offenders).
	// 6 hex zeros = 24 bits = ~16M hashes = way too long (cap for extreme cases).
	// Base 4 gives real browsers a quick solve; escalates for repeat hostile IPs.
	difficulty := 4 + strikes
	if difficulty > 5 {
		difficulty = 5
	}
	// Generate a random hex challenge
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	challenge := make([]byte, 16)
	hexChars := "0123456789abcdef"
	for i := range challenge {
		challenge[i] = hexChars[rnd.Intn(16)]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"challenge":  string(challenge),
		"difficulty": difficulty,
		"ip":         rawIP,
	})
}

// handlePowVerify validates the PoW solution, records energy mined in
// attack_energy, and issues the challenge cookie on success.
func handlePowVerify(w http.ResponseWriter, r *http.Request) {
	// CORS preflight — browser sends OPTIONS before the actual POST when
	// Content-Type: application/json is used. Without this, the fetch fails
	// with a CORS error and the user sees "Verification failed" forever.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Challenge  string `json:"challenge"`
		Nonce      string `json:"nonce"`
		Difficulty int    `json:"difficulty"`
		Hashes     int    `json:"hashes"`
		IP         string `json:"ip"`
		UA         string `json:"ua"`
		Redirect   string `json:"redirect"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "bad request"})
		return
	}
	// Recompute SHA-256(challenge|nonce) and verify
	candidate := req.Challenge + "|" + req.Nonce
	h := sha256.Sum256([]byte(candidate))
	hashHex := fmt.Sprintf("%x", h)
	prefix := ""
	for i := 0; i < req.Difficulty; i++ {
		prefix += "0"
	}
	if hashHex[:min(len(hashHex), req.Difficulty)] != prefix {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "invalid solution"})
		return
	}
	// Record energy mined in attack_energy
	energy := pow.FibEnergy(req.Difficulty)
	pow.RecordMined(req.IP, req.Difficulty, candidate, energy)
	// Issue the challenge cookie
	ip := normalizeIP(req.IP)
	cookie := pages.GenerateSlidingCookie(ip, req.UA)
	http.SetCookie(w, &http.Cookie{
		Name: "aegis_challenge", Value: cookie, Path: "/",
		MaxAge: 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	// Label this IP as benign training data — a real browser solved the PoW.
	// Write to BOTH live_events.jsonl (for daily retrain) AND security_events
	// (for dashboard visibility). Without the security_events row, PoW-verified
	// visitors are invisible in the dashboard "Recent Intercepts" panel.
	logLiveEvent(ip, "/", req.UA, 0, 0.0, "low", "BENIGN_POW")
	ts := nowStamp()
	agencyID := fmt.Sprintf("POW-%08X-%04X", uint32(time.Now().Unix()>>16), uint16(time.Now().Unix()&0xFFFF))
	geo := enrichment.GetGeoIP(ip)
	db.WriteLock()
	logSecurityEvent(ip, geo["country"], geo["city"], "BENIGN_POW", "low",
		req.UA, "/", 128, 65535, 1460, "", ts, agencyID,
		0.0, 0.0, 0.0, os.Getenv("PRIMARY_SITE"))
	db.WriteUnlock()
	appendShieldLog(fmt.Sprintf("[POW-VERIFIED] %s solved %d-bit PoW in %d hashes — labeled benign", ip, req.Difficulty, req.Hashes))
	w.Header().Set("Content-Type", "application/json")
	redirect := req.Redirect
	if redirect == "" {
		redirect = "/"
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"energy":   energy,
		"redirect": redirect,
	})
}

// handleRegisterSite registers a new client site in the shield_routes DB table.
// POST /api/v1/register-site with JSON body: {"domain": "example.com", "backend_url": "http://10.0.0.1:8080"}
// Shield auto-routes traffic for this domain to the backend. No nginx config changes needed.
// Self-hosted deb customers use this to add their site without editing nginx.
func handleRegisterSite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "POST required"})
		return
	}

	var req struct {
		Domain     string `json:"domain"`
		BackendURL string `json:"backend_url"`
		SiteID     string `json:"site_id"`
		Tier       string `json:"tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "bad request"})
		return
	}
	if req.Domain == "" || req.BackendURL == "" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "domain and backend_url required"})
		return
	}
	if req.Tier == "" {
		req.Tier = "community"
	}

	d, err := db.Open(config.BrainDB)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}
	defer d.Close()

	_, err = d.Exec(`INSERT OR REPLACE INTO shield_routes (domain, backend_url, site_id, tier, active, updated_at)
		VALUES (?, ?, ?, ?, 1, datetime('now'))`,
		req.Domain, req.BackendURL, req.SiteID, req.Tier)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}

	// Also add www variant
	if !strings.HasPrefix(req.Domain, "www.") {
		d.Exec(`INSERT OR REPLACE INTO shield_routes (domain, backend_url, site_id, tier, active, updated_at)
			VALUES (?, ?, ?, ?, 1, datetime('now'))`,
			"www."+req.Domain, req.BackendURL, req.SiteID, req.Tier)
	}

	appendShieldLog(fmt.Sprintf("[REGISTER] %s → %s (tier=%s)", req.Domain, req.BackendURL, req.Tier))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"domain":  req.Domain,
		"backend": req.BackendURL,
		"tier":    req.Tier,
	})
}

func handleProfilerStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(profiler.GetStats())
}

func handleIOCReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	ioc.SaveIOCReport()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "saved", "file": config.EvidenceDir + "/ioc-report.json"})
}

func handleAbuseStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(abuse.GetAbuseStats())
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	ua := r.UserAgent()
	path := r.URL.Path
	rawIP := normalizeIP(ip)

	if isStaticAsset(path) {
		proxyToLanding(w, r)
		return
	}
	if path == "/test-bot-connection" || path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "agent": "v5.0", "version": "5.0.0"})
		return
	}

	isGoodBotUser := isGoodBot(ua)
	isTrustedIP := isTrusted(rawIP)

	// Cookie bypass — known-good browsers skip everything.
	cookieHeader := r.Header.Get("Cookie")
	challengeMatch := challengeRegexp.FindStringSubmatch(cookieHeader)
	cookieVal := getString(challengeMatch, 1)
	cookieValid := pages.ValidateChallengeCookie(cookieVal, ua, rawIP)
	// Debug: log the first 8 chars of each input to ValidateChallengeCookie
	expectedHash := ""
	if cookieVal != "" && len(ua) > 0 && rawIP != "" {
		expectedHash = pages.GenerateSlidingCookie(rawIP, ua)[:8]
	}
	fmt.Fprintf(os.Stderr, "[SHIELD-DEBUG] cookie=%q valid=%v rawIP=%q ua=%q expected_prefix=%q path=%s\n", cookieVal[:min(len(cookieVal),8)], cookieValid, rawIP, ua[:min(len(ua),30)], expectedHash, path)
	if cookieValid {
		cadence.RecordVisit(os.Getenv("PRIMARY_SITE"), path, time.Now().UnixMicro(), true)
		proxyToLanding(w, r)
		return
	}

	// PoW-gated paths: login, checkout, account pages — ALWAYS show PoW.
	pathLower := strings.ToLower(path)
	isGatedPath := false
	gatedPatterns := []string{
		"wp-login", "/login", "/wp-admin",
		"/checkout", "/my-account", "/cart", "/account",
		"/register", "/signup", "/xmlrpc",
		"/reset-password", "/forgot-password",
	}
	for _, p := range gatedPatterns {
		if strings.Contains(pathLower, p) {
			isGatedPath = true
			break
		}
	}
	if isGatedPath {
		profiler.Track(rawIP, ua, path, "", "")
		html := pages.ChallengePage(rawIP, ua, path, config.StrikeURL)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		w.Write([]byte(html))
		return
	}

	// Trusted/good bot bypass
	if isTrustedIP || isGoodBotUser {
		proxyToLanding(w, r)
		return
	}

	// Hot-path: already-blocked IPs are dropped immediately — no classification
	// cost. The durable blockledger table is the source of truth (kept in sync
	// by the clusterer running on the Soul).
	if banned, reason := blockledger.IsBlocked(rawIP); banned {
		appendShieldLog(fmt.Sprintf("[BLOCKLEDGER] %s pre-blocked (%s) → GCP", rawIP, reason))
		dispatchStrike(rawIP, "AEGIS-REPEAT-"+reason)
		// Route via /t/ — GCP tracker_hit fingerprints THEN serves weaponized page.
		http.Redirect(w, r, config.StrikeURL+"/t/block-repeat", 302)
		return
	}

	// Blast detection: if an IP fires more than 5 requests in 10 seconds,
	// block it immediately without waiting for C engine classification.
	// But log the IP first so we have forensic evidence.
	if isBlast(rawIP) {
		if !blockledger.IsBlockedNow(rawIP) {
			geo := enrichment.GetGeoIP(rawIP)
	ts := nowStamp()
			fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:blast", rawIP))))[:16]
			agencyID := fmt.Sprintf("BLAST-%08X-%04X", uint32(time.Now().Unix()>>16), uint16(time.Now().Unix()&0xFFFF))
			logSecurityEvent(rawIP, geo["country"], geo["city"], "BLAST", "critical",
				ua, path, 128, 65535, 1460, fingerprint, ts, agencyID,
				0.95, 0.9, 0.7, "shield")
			logForensicReport(rawIP, "BLAST", "critical", fingerprint, ua, path,
				0.95, 0.9, 0.7, geo, 128, 65535, 1460, "BLAST", agencyID, ts, "shield")
			appendShieldLog(fmt.Sprintf("[BLAST] %s logged + blocked — rapid-fire detected", rawIP))
		}
		blockledger.BlockIP(rawIP, "BLAST", "shield", 1)
		dispatchStrike(rawIP, "AEGIS-BLAST")
		// Route via /t/ — GCP tracker_hit fingerprints THEN serves weaponized page.
		http.Redirect(w, r, config.StrikeURL+"/t/blast-scanner", 302)
		return
	}

	// Honeypot trap paths
	if isTrapPath(path) {
		serveTrap(w, r, rawIP, ua, path)
		return
	}

	// CLASSIFY — first-time visitor (no valid challenge cookie).
	result := classifyRequest(ip, ua, path, r.Method, r.Header.Get("Referer"),
		r.Header.Get("Accept-Language"), getContentLength(r))

	fmt.Fprintf(os.Stderr, "[SHIELD-DEBUG] classifyRequest returned: Hostile=%d Tier=%d Error=%q Consensus=%.4f\n",
		result.Hostile, result.Tier, result.Error, result.Consensus)

	if result.Trusted || result.Error != "" {
		proxyToLanding(w, r)
		return
	}

	// Persist every non-trusted classification exactly once. This guarantees
	// real hostile traffic is recorded even if the C engine returns a low score.
	siteID := r.Host
	if siteID == "" {
		siteID = os.Getenv("PRIMARY_SITE")
	}
	persistClassificationResult(rawIP, ua, path, result, siteID)

	// If hostile, redirect to GCP counter-attack server immediately.
	// ponytail: route only clearly hostile verdicts (tier 4, OR hostile +
	// attack-tool UA + sensitive path + tier 3) to GCP Strike. C engine
	// false positives without these signals fall through to challenge page
	// so real browsers can solve the PoW and get a cookie. Add when: the
	// C engine retrains on real benign traffic and false positives drop.
	//
	// LOWERED THRESHOLD: tier 4 OR (hostile UA + consensus >= 0.7) ONLY.
	// This lets more real-browser traffic reach the PoW challenge, get
	// labeled BENIGN_POW, and feed the daily retrain. Without this, the
	// C engine never sees benign traffic in training and stays stuck at
	// 99% hostile. Once the retrain balance shifts, raise this back to
	// consensus >= 0.85.
	hostileUA := isHostileUA(ua)
	strongHostile := result.Hostile == 1 && (result.Tier == 4 || (hostileUA && result.Consensus >= 0.7))
	if strongHostile || result.Tier == 4 {
		profiler.RecordStrike(rawIP)
		geo := enrichment.GetGeoIP(rawIP)
		profiler.Track(rawIP, ua, path, geo["country"], geo["asn"])
		ioc.RecordIOC("ipv4-addr", rawIP, fmt.Sprintf("Hostile: %s", path), result.Consensus, []string{"T1595"})
		threatfeed.PushEvent(threatfeed.ThreatEvent{
			Timestamp: time.Now().Format(time.RFC3339),
			IP: rawIP, Actor: result.Actor, Consensus: result.Consensus,
			Severity: map[int]string{4: "critical", 3: "high"}[result.Tier],
			Reason: result.Reason, Country: geo["country"],
		})
		logFBIEvidence(rawIP, "HIGH_THREAT_BLOCK", result)

		// === DEEP-INTELLIGENCE WIRE ===
		// 1. Silicon DNA — write/update the durable identity row
		identity.Record(rawIP, ua, path, result.Fingerprint, 1)

		// 2. Synaptic memory — per-IP long-term memory with URIEL state + disharmony
		synaptic.RecordMemorize(rawIP, ua, path, geo["country"], result.Reason,
			result.Fingerprint, "", "", 1)

		// 3. Coherence gate — φ-signature harmonic lock keyed on the fingerprint
		harmonic := coherence.Evaluate(result.Fingerprint, result.Consensus, config.EnsembleThreshold)
		coherence.Record(result.Fingerprint, fmt.Sprintf("phi:%.4f", result.Consensus), harmonic)

		// 4-5. Federal case mapping + nation-state attribution are already
		// captured inside logForensicReport (called by persistClassificationResult),
		// so do not write a duplicate forensic_reports row here.

		// 6-7. Auditor cross-check and federal/nation-state mapping are already
		// captured inside logForensicReport (called by persistClassificationResult).

		// 8. Real-time LLM enrichment — call Soul /security/check for intent unmasking
		// (Run in this goroutine — adds ~1s for tier-3+ but every event gets LLM-assessed.)
		llmSummary := soulEnrich(rawIP, ua, path, result.Reason, geo)
		if llmSummary != "" {
			// Persist the unmasked intent back to the latest forensic_report row
			persistIntentUnmask(rawIP, llmSummary)
		}

		// 8. Lattice signal — record the agent's input → output pair for validation
		lattice.RecordSignal(1,
			fmt.Sprintf("shield|%s|%s", rawIP, path),
			fmt.Sprintf("tier=%d consensus=%.4f actor=%s", result.Tier, result.Consensus, result.Actor),
			"validated", result.Consensus)

		// 9. Cadence — record this request timing for harmonic-delay tracking
		cadence.RecordVisit(os.Getenv("PRIMARY_SITE"), path, time.Now().UnixMicro(), false)

		// 10. Blockledger — durable blocked_ips row (kernel-level iptables is the
		// tier-4 escalation; blockledger is the persistent truth).
		blockledger.BlockIP(rawIP, result.Reason, os.Getenv("PRIMARY_SITE"), 1)
		if result.Tier == 4 {
			synaptic.Blackhole(rawIP, 168) // 7-day blackhole for tier-4
		}

		// Write to shield_soul.log for dashboard HUD
		appendShieldLog(fmt.Sprintf("[AEGIS-ALPHA] Score=%.4f | Hostile=%d", result.Alpha, result.Hostile))
		appendShieldLog(fmt.Sprintf("[AEGIS-BETA] Anomaly=%.4f | Consensus=%.4f", result.Beta, result.Consensus))
		appendShieldLog(fmt.Sprintf("[AEGIS-CONSENSUS] Score=%.4f | Threshold=0.618 | Hostile=%d", result.Consensus, result.Hostile))
		appendShieldLog(fmt.Sprintf("shield BLOCK ? %s cons=", rawIP))

		dispatchStrike(rawIP, fmt.Sprintf("AEGIS-%s", result.Reason))

		// Route hostile traffic via /t/<bait-id> — GCP tracker_hit
		// fingerprints the visitor (device fingerprint + IP geo) THEN
		// the middleware injects the storage-bomb fill script. Device
		// fingerprint clusters same-human across Tor/VPN rotations.
		if result.Tier == 4 {
			voidpunisher.DeployIPTablesDrop(rawIP)
			http.Redirect(w, r, config.StrikeURL+"/t/strike-tarpit", 302)
		} else {
			http.Redirect(w, r, config.StrikeURL+"/t/wp-login-attempt", 302)
		}
		return
	}

	// First-time visitor (no valid cookie) — serve JS PoW challenge.
	// Real browsers solve it in <1s and get the aegis_challenge cookie,
	// bypassing classification on subsequent requests.
	profiler.Track(rawIP, ua, path, "", "")
	html := pages.ChallengePage(rawIP, ua, path, config.StrikeURL)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(403)
	w.Write([]byte(html))
}

func classifyRequest(ip, ua, path, method, referer, acceptLang string, contentLength int) types.ClassifyResult {
	rawIP := normalizeIP(ip)
	if isTrusted(rawIP) {
		return types.ClassifyResult{Trusted: true}
	}

	ttl, window, mss := 128, 65535, 1460
	ev := extractor.Event{
		IP: rawIP, UserAgent: ua, RequestURI: path, Method: method,
		HTTPReferer: referer, AcceptLanguage: acceptLang, ContentLength: contentLength,
		TTL: ttl, Window: window, MSS: mss,
	}
	features := extractor.ExtractFeatures(ev)
	verdict, err := cengine.Classify(features, rawIP)
	if verdict == nil {
		// Defensive: treat a nil verdict as a C-engine error and fall through
		// to the rule-based fallback path.
		if err == nil {
			err = fmt.Errorf("nil verdict from C engine")
		}
	} else {
		fmt.Fprintf(os.Stderr, "[SHIELD-DEBUG] C engine: hostile=%d consensus=%.4f err=%v features=%v\n",
			verdict.Hostile, verdict.Consensus, err, features)
	}
	if err != nil {
		// C engine failed — use rule-based fallback
		score := 0
		uaLower := strings.ToLower(ua)
		pathLower := strings.ToLower(path)
		attackTools := []string{"sqlmap", "nmap", "nikto", "gobuster", "masscan", "zgrab", "wpscan"}
		for _, tool := range attackTools {
			if strings.Contains(uaLower, tool) {
				score = 80
			}
		}
		suspicious := []string{".env", ".git", "wp-admin", "wp-login", "xmlrpc", "phpmyadmin", "actuator", "heapdump"}
		for _, pat := range suspicious {
			if strings.Contains(pathLower, pat) {
				score = 70
			}
		}
		if score >= 50 {
			verdict = &types.CEngineVerdict{
				Consensus: float64(score) / 100.0,
				Alpha:     float64(score) / 100.0,
				Beta:      0.5,
				Gamma:     0.5,
				Hostile:   1,
			}
		} else {
			// C engine failed and the request is not obviously malicious.
			// Do not silently treat it as trusted; return a low-tier result so
			// it is still logged and can be audited later.
			actor := classifyActor(ua)
			fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%d", rawIP, ua[:min(len(ua), 30)], ttl, mss))))[:16]
			return types.ClassifyResult{
				Hostile: 0, Consensus: 0.1,
				Alpha: 0.1, Beta: 0.1, Gamma: 0.1,
				Tier: 1, Actor: actor, Fingerprint: fingerprint,
				Reason: fmt.Sprintf("CENGINE_ERROR: %v", err),
			}
		}
	}

	consensus := verdict.Consensus
	hostile := verdict.Hostile

	pathLower := strings.ToLower(path)
	isHoneytoken := false
	for _, h := range config.Honeypaths {
		if strings.Contains(pathLower, h) {
			isHoneytoken = true
			break
		}
	}
	if isHoneytoken && consensus < 0.66 {
		consensus = 0.66 + verdict.Audit.Confidence*0.1
		hostile = 1
	}

	var tier int
	if verdict.Audit.Confidence >= 0.9 || (hostile == 1 && consensus >= 0.9) {
		tier = 4
	} else if hostile == 1 || consensus >= 0.618 {
		tier = 3
	} else if consensus >= 0.5 {
		tier = 2
	} else {
		tier = 1
	}

	if tier == 2 && verdict.Audit.RequiresLLM == 1 {
		llmResult := triadclient.ShieldCheck(map[string]interface{}{
			"ip": rawIP, "ua": ua, "path": path, "method": method,
			"consensus": consensus, "rules_score": 0,
		})
		if v, ok := llmResult["verdict"].(string); ok && v == "block" {
			tier = 3
			hostile = 1
			consensus = 0.85
		}
	}

	actor := classifyActor(ua)
	geo := enrichment.GetGeoIP(rawIP)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%d", rawIP, ua[:min(len(ua), 30)], ttl, mss))))[:16]
	reason := "PATH_BLOCK_HOSTILE"
	if !isHoneytoken {
		reason = fmt.Sprintf("CONSENSUS_%.3f", consensus)
	}

	if tier >= 3 && geo["country"] != "" && geo["country"] != "XX" {
		abuse.SendAbuseReport(rawIP, geo["asn"], geo["isp"], geo["country"],
			reason, fmt.Sprintf("Consensus: %.3f, Actor: %s, UA: %s", consensus, actor, ua[:min(len(ua), 50)]))
	}

	// Report telemetry (mandatory for community edition)
	if os.Getenv("TELEMETRY") == "true" {
		go reportTelemetry(features, hostile, consensus, reason, rawIP)
	}

	return types.ClassifyResult{
		Hostile: hostile, Consensus: consensus,
		Alpha: verdict.Alpha, Beta: verdict.Beta, Gamma: verdict.Gamma,
		Tier: tier, Actor: actor, Fingerprint: fingerprint, Reason: reason,
	}
}

// persistClassificationResult writes security_events, forensic_reports and
// live_events once for any non-trusted classification. This is the single point
// of persistence in the shield, eliminating double-writes and ensuring real
// hostile traffic is always recorded even when the C engine returns a low score.
func persistClassificationResult(ip, ua, path string, result types.ClassifyResult, siteID string) {
	ttl, window, mss := 128, 65535, 1460
	geo := enrichment.GetGeoIP(ip)
	severity := map[int]string{4: "critical", 3: "high", 2: "medium", 1: "low"}[result.Tier]
	if severity == "" {
		severity = "low"
	}
	ts := nowStamp()
	agencyID := fmt.Sprintf("AEGIS-%s-%08X-%04X",
		result.Actor[:min(len(result.Actor), 4)],
		uint32(time.Now().Unix()>>16),
		uint16(time.Now().Unix()&0xFFFF))

	db.WriteLock()
	logSecurityEvent(ip, geo["country"], geo["city"], result.Reason, severity,
		ua, path, ttl, window, mss, result.Fingerprint, ts, agencyID,
		result.Consensus, result.Alpha, result.Beta, siteID)
	logForensicReport(ip, result.Reason, severity, result.Fingerprint, ua, path,
		result.Consensus, result.Alpha, result.Beta, geo, ttl, window, mss,
		result.Actor, agencyID, ts, siteID)
	db.WriteUnlock()
	logLiveEvent(ip, path, ua, result.Hostile, result.Consensus, severity, result.Actor)
	// Log every classification to shield_soul.log so the HUD always has fresh data
	appendShieldLog(fmt.Sprintf("CLASSIFY %s %s Hostile=%d Consensus=%.4f Tier=%d",
		ip[:min(len(ip), 20)], path[:min(len(path), 40)], result.Hostile, result.Consensus, result.Tier))
}

func logSecurityEvent(ip, country, city, reason, severity, ua, path string,
	ttl, window, mss int, fingerprint, ts, agencyID string, consensus, alpha, beta float64, siteID string) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SHIELD-DB] open error: %v\n", err)
		return
	}
	defer d.Close()
	_, execErr := d.Exec(`INSERT INTO security_events
		(ip, country_code, city, reason, severity, user_agent, request_uri,
		 tcp_ttl, tcp_window, tcp_mss, tls_ja3, evidence, strikes,
		 created_at, fingerprint, site_id, agency_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ip, country, city, reason, severity, ua[:min(len(ua), 255)], path,
		ttl, window, mss, fingerprint,
		fmt.Sprintf(`{"consensus":%.4f,"alpha":%.4f,"beta":%.4f}`, consensus, alpha, beta),
		1, ts, fingerprint, siteID, agencyID)
	if execErr != nil {
		fmt.Fprintf(os.Stderr, "[SHIELD-DB] insert error: ip=%s err=%v\n", ip, execErr)
	}
}

func logForensicReport(ip, reason, severity, fingerprint, ua, path string,
	consensus, alpha, beta float64, geo map[string]string, ttl, window, mss int,
	actor, agencyID, ts, siteID string) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()

	// Federal case mapping — write SAR/FBI/MITRE into the row + set
	// nation_state_attribution via the ASN heuristic.
	fc := federal.MapFromPath(path, reason)
	fc.Nation = nationstate.Attribute(geo["asn"], geo["country"], geo["isp"], geo["org"])
	mappingJSON, _ := json.Marshal(fc)

	// Auditor cross-check stitched into the synthesis JSON
	aud := auditor.Query(ip, []float64{alpha, beta, consensus})
	synthesis := map[string]interface{}{
		"consensus":           consensus,
		"alpha":               alpha,
		"beta":                beta,
		"auditor_hostile":     aud.Hostile,
		"auditor_confidence":  aud.Confidence,
		"threat_resonance":   aud.Resonance,
		"nation_state":        fc.Nation,
		"federal_case":        fc.SARCode,
		"fbi_label":           fc.FBILabel,
		"mitre":               fc.MITREIDs,
	}
	synthesisJSON, _ := json.Marshal(synthesis)

	d.Exec(`INSERT INTO forensic_reports
		(ip, reason, severity, fingerprint, user_agent, request_uri, evidence,
		 country, city, tcp_window, tcp_ttl, tcp_mss, isp_asn, tls_ja3,
		 strikes, site_id, created_at, deepseek_model, intent_category, target_uri,
		 behavioral_fingerprint, threat_level, physical_id, tcp_signature,
		 synthesis, federal_mapping, nation_state_attribution)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ip, reason, severity, fingerprint, ua[:min(len(ua), 255)], path,
		synthesisJSON,
		geo["country"], geo["city"], window, ttl, mss, geo["asn"], fingerprint,
		1, siteID, ts, "Go Engine", actor, path,
		fingerprint, severity, agencyID, fingerprint,
		synthesisJSON, string(mappingJSON), fc.Nation)
}

// soulEnrich fires a real-time LLM call to Soul /security/check for every
// tier-3+ block, returning a one-line intent summary (attacker_type + recommendation).
// Returns "" if the Soul is unreachable or the API key isn't set.
func soulEnrich(ip, ua, path, reason string, geo map[string]string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	body := map[string]interface{}{
		"ip":       ip,
		"ua":       ua,
		"path":     path,
		"method":   "GET",
		"reason":   reason,
		"country":  geo["country"],
		"asn":      geo["asn"],
		"consensus": 0.85,
	}
	data, _ := json.Marshal(body)
	resp, err := client.Post("http://127.0.0.1:3007/security/check",
		"application/json", bytes.NewReader(data))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var out struct {
		SoulAssessment string  `json:"soul_assessment"`
		AttackerType   string  `json:"attacker_type"`
		Confidence     float64 `json:"soul_confidence"`
		Recommendation string  `json:"recommendation"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	parts := []string{}
	if out.AttackerType != "" {
		parts = append(parts, "type="+out.AttackerType)
	}
	if out.SoulAssessment != "" {
		parts = append(parts, "assess="+out.SoulAssessment)
	}
	if out.Recommendation != "" {
		parts = append(parts, "rec="+out.Recommendation)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " | ")
}

// persistIntentUnmask writes the Soul's LLM-derived intent back onto the
// latest forensic_reports row for the given IP.
func persistIntentUnmask(ip, summary string) {
	if ip == "" || summary == "" {
		return
	}
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	d.Exec(`UPDATE forensic_reports SET intent_unmasked = ?
		WHERE ip = ? AND id = (SELECT MAX(id) FROM forensic_reports WHERE ip = ?)`,
		summary, ip, ip)
}

// extractorToFloats flattens a ClassifyResult into the float vector shape the
// auditor expects (alpha, beta, consensus).
func extractorToFloats(r types.ClassifyResult) []float64 {
	return []float64{r.Alpha, r.Beta, r.Consensus}
}

func logFBIEvidence(ip, eventType string, result types.ClassifyResult) {
	geo := enrichment.GetGeoIP(ip)
	event := types.FBIEvidence{
		IP: ip, EventType: eventType,
		Reason: result.Reason,
		ThreatScore: int(result.Consensus * 100),
		TriadScores: types.TriadScores{
			Shield: result.Alpha, Audit: 0.8, Soul: result.Beta,
			Consensus: result.Consensus, Final: int(result.Consensus * 100),
		},
		Geo: types.GeoIPResult{Country: geo["country"], City: geo["city"], ASN: geo["asn"], ISP: geo["isp"]},
		TCPDNA: types.TCPDNA{TTL: 128, Window: 65535, MSS: 1460},
		MITREAttackIDs: []string{"T1595"},
	}
	fbi.WriteEvidence(event)
}

func logLiveEvent(ip, path, ua string, hostile int, consensus float64, severity, actor string) {
	f, err := os.OpenFile(config.LiveFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	entry := map[string]interface{}{
		"ts": nowStamp(), "ip": ip,
		"path": path, "ua": ua[:min(len(ua), 100)],
		"hostile": hostile, "consensus": consensus,
		"severity": severity, "actor": actor,
	}
	data, _ := json.Marshal(entry)
	f.Write(data)
	f.WriteString("\n")
}

func dispatchStrike(ip, reason string) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("%s/strike?ip=%s&reason=%s", config.StrikeURL, ip, reason)
	resp, err := client.Post(url, "text/plain", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[STRIKE] Error: %v\n", err)
		return
	}
	resp.Body.Close()
	fmt.Printf("[STRIKE] Dispatched to GCP for %s (%s)\n", ip, reason)
	appendShieldLog(fmt.Sprintf("[AEGIS-STRIKE] GCP counter-strike dispatched for %s (%s) to %s (http=200)", ip, reason, config.StrikeURL))
}

func getStats() map[string]interface{} {
	stats := map[string]interface{}{
		"service": "v5.0", "version": "5.0.0",
		"uptime": time.Since(startTime).String(),
	}
	d, err := db.Open(config.BrainDB)
	if err == nil {
		defer d.Close()
		var cnt int
		d.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&cnt)
		stats["security_events"] = cnt
		d.QueryRow("SELECT COUNT(*) FROM forensic_reports").Scan(&cnt)
		stats["forensic_reports"] = cnt
	}
	stats["fbi_cases"] = fbi.GetEvidenceStats()["total"]
	stats["blocked_ips"] = len(voidpunisher.GetBlockedIPs())
	stats["profiler"] = profiler.GetStats()
	stats["ioc_count"] = len(ioc.GetIOCs())
	stats["abuse_reports"] = abuse.GetAbuseStats()
	return stats
}

var startTime = time.Now()

var trapPaths = map[string]bool{
	"/.env": true, "/.git/config": true, "/.git/HEAD": true,
	"/.aws/credentials": true, "/wp-admin": true, "/wp-login.php": true,
	"/xmlrpc.php": true, "/phpmyadmin": true, "/adminer.php": true,
	"/jenkins": true, "/gitlab": true, "/cpanel": true, "/webmail": true,
	"/.htpasswd": true, "/phpinfo.php": true, "/info.php": true,
	"/backup.sql": true, "/database.sql": true, "/debug.log": true,
	"/server-status": true, "/actuator": true, "/heapdump": true,
}

func isTrapPath(path string) bool {
	pathLower := strings.ToLower(path)
	for p := range trapPaths {
		if strings.Contains(pathLower, p) {
			return true
		}
	}
	return false
}

func serveTrap(w http.ResponseWriter, r *http.Request, ip, ua, path string) {
	// Capture attacker behavior
	profiler.Track(ip, ua, path, "", "")
	ioc.RecordIOC("ipv4-addr", ip, fmt.Sprintf("Honeypot probe: %s", path), 0.9, []string{"T1595"})

	// Persist the trap hit through the shared classification path so
	// security_events, forensic_reports, and live_events are written exactly
	// once and stay consistent with normal hostile classifications.
	siteID := r.Host
	if siteID == "" {
		siteID = os.Getenv("PRIMARY_SITE")
	}
	result := types.ClassifyResult{
		Hostile:     1,
		Consensus:   1.0,
		Alpha:       0.9,
		Beta:        0.5,
		Gamma:       0.5,
		Tier:        3,
		Actor:       "HONEYPOT_PROBE",
		Fingerprint: "honeypot",
		Reason:      "HONEYPOT_PROBE",
	}
	persistClassificationResult(ip, ua, path, result, siteID)

	// Deep-intelligence wire for trap hits (same as hostile blocks)
	identity.Record(ip, ua, path, "honeypot", 1)
	synaptic.RecordMemorize(ip, ua, path, "", "high", "honeypot-probe", "", "", 1)
	blockledger.BlockIP(ip, "HONEYPOT_PROBE", os.Getenv("PRIMARY_SITE"), 1)
	trapledger.RecordVisit(ip, ua, r.Header.Get("Referer"), classifyHoneypath(path), "probe")

	// Push to threat feed
	ts := nowStamp()
	threatfeed.PushEvent(threatfeed.ThreatEvent{
		Timestamp: ts, IP: ip, Actor: "HONEYPOT_PROBE",
		Consensus: 1.0, Severity: "high", Reason: fmt.Sprintf("Honeypot probe: %s", path),
	})

	// Dispatch GCP strike for tarpit + credential capture
	dispatchStrike(ip, "AEGIS-HONEYPOT-PROBE")

	// Redirect to GCP for heavy offensive weapons
	http.Redirect(w, r, config.StrikeURL+path, 302)
}

// classifyHoneypath reduces a trap path to the honeypot family (wp-login,
// git-exposure, env-exposure, etc.) — used to label trap_visits.stage.
func classifyHoneypath(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "wp-login"), strings.Contains(p, "wp-admin"):
		return "wp-login"
	case strings.Contains(p, ".git"):
		return "git-exposure"
	case strings.Contains(p, ".env"):
		return "env-exposure"
	case strings.Contains(p, "phpmyadmin"), strings.Contains(p, "adminer"):
		return "db-admin"
	case strings.Contains(p, "actuator"), strings.Contains(p, "heapdump"):
		return "spring-exploit"
	case strings.Contains(p, "console"):
		return "console-probe"
	default:
		return "path-probe"
	}
}

func proxyToLanding(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 10 * time.Second}
	backend := config.BackendForHost(r.Host)
	fmt.Fprintf(os.Stderr, "[SHIELD-DEBUG] proxyToLanding host=%q backend=%q path=%s\n", r.Host, backend, r.URL.Path)
	req, err := http.NewRequest(r.Method, backend+r.URL.Path, r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<!DOCTYPE html><html><head><title>Aegis-SIGMA</title></head><body><h1>Aegis-SIGMA</h1></body></html>"))
		return
	}
	for _, h := range []string{"Host", "User-Agent", "Accept", "Accept-Language", "Referer", "X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	// Always tell the backend the original request was HTTPS (nginx terminates TLS)
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := client.Do(req)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<!DOCTYPE html><html><head><title>Aegis-SIGMA</title></head><body><h1>Aegis-SIGMA</h1></body></html>"))
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		lk := strings.ToLower(k)
		if lk != "transfer-encoding" && lk != "connection" {
			w.Header().Set(k, v[0])
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

// loadConfigEnv reads /etc/aegis-sigma/config.env and overrides defaults.
// Self-hosted deb customers configure StrikeURL and BackendURL here.
// Format: KEY=VALUE, one per line. Lines starting with # are ignored.
func loadConfigEnv() {
	const configFile = "/etc/aegis-sigma/config.env"
	data, err := os.ReadFile(configFile)
	if err != nil {
		return // no config file — use compiled defaults
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "STRIKE_URL":
			if v == "aegis-hosted" {
				config.StrikeURL = os.Getenv("STRIKE_URL")
			} else if v == "local" || v == "" {
				// Use Shield's own /t/<id> as the tracker —
				// self-hosted mode. Point at localhost so
				// 302 redirects land on Shield's own handler.
				config.StrikeURL = fmt.Sprintf("http://127.0.0.1:%d", config.ShieldPort)
			} else {
				config.StrikeURL = v
			}
			fmt.Printf("[SHIELD] StrikeURL=%s (from config.env)\n", config.StrikeURL)
		case "BACKEND_URL":
			if v != "" {
				config.LandingURL = v
				fmt.Printf("[SHIELD] BackendURL=%s (from config.env)\n", config.LandingURL)
			}
		}
	}
}

// normalizeIP strips the IPv6-mapped prefix and any TCP port suffix so that the
// IP can be used as a stable per-client identity key. Cookies, PoW challenges,
// blockledger entries and GeoIP lookups all go through this. Without it the
// ephemeral source port (which changes on every TCP connection) was being
// baked into the challenge cookie hash, so the cookie validated exactly once
// and every subsequent request from a real browser was re-challenged.
func normalizeIP(ip string) string {
	ip = strings.Replace(ip, "::ffff:", "", 1)
	// Trim everything from the last ':' onward when it looks like host:port.
	// IPv6 literals in brackets are left alone; bare host:port (IPv4 or hostname)
	// gets the port removed. IPv6 without brackets is uncommon at this layer.
	if i := strings.LastIndex(ip, ":"); i >= 0 {
		tail := ip[i+1:]
		if _, err := strconv.Atoi(tail); err == nil && tail != "" {
			ip = ip[:i]
		}
	}
	return ip
}

func isTrusted(ip string) bool {
	// Infra-only bypass: WireGuard mesh + loopback. No hardcoded customer IPs.
	for _, p := range config.TrustedPrefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	// Customer + admin trust lives in the trusted_sources DB table. Site
	// admins add rows there (type='manual' for hand-vouched, type='auto'
	// for PoW-solved IPs promoted to trust after repeated benign visits).
	if d, err := db.Open(config.BrainDB); err == nil {
		defer d.Close()
		var n int
		d.QueryRow("SELECT COUNT(*) FROM trusted_sources WHERE source = ? AND (type = 'manual' OR type = 'auto')", ip).Scan(&n)
		if n > 0 {
			return true
		}
	}
	return false
}

func isGoodBot(ua string) bool {
	for _, b := range config.GoodBots {
		if strings.Contains(ua, b) {
			return true
		}
	}
	return false
}

// isHostileUA reports whether the UA string matches a known attack tool or
// generic scripting library (curl, python-requests, masscan, nmap, etc.).
// Used to gate GCP Strike tarpit redirects — borderline C-engine verdicts
// without a hostile UA get the challenge page instead of the tarpit.
func isHostileUA(ua string) bool {
	if ua == "" {
		return true
	}
	hostileList := []string{
		"curl", "wget", "python-requests", "python-urllib", "go-http-client",
		"java/", "libwww", "perl", "scrapy", "nessus", "openvas", "burp",
		"faraday", "l9scan", "leakix", "nmap", "nikto", "sqlmap", "masscan",
		"gobuster", "zgrab", "dirbuster", "wpscan", "arachni", "w3af",
		"havij", "acunetix", "hydra", "medusa",
	}
	uaLower := strings.ToLower(ua)
	for _, h := range hostileList {
		if strings.Contains(uaLower, h) {
			return true
		}
	}
	return false
}

func getContentLength(r *http.Request) int {
	if v := r.Header.Get("Content-Length"); v != "" {
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

func getString(matches []string, idx int) string {
	if idx < len(matches) {
		return matches[idx]
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isStaticAsset(path string) bool {
	exts := []string{".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff2", ".ttf", ".eot", ".webp", ".avif"}
	for _, ext := range exts {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

func classifyActor(ua string) string {
	lower := strings.ToLower(ua)
	if containsAny(lower, "nmap", "masscan", "zmap", "shodan") {
		return "SCANNER"
	}
	if containsAny(lower, "sqlmap", "nikto", "gobuster", "metasploit") {
		return "EXPLOIT"
	}
	if containsAny(lower, "mirai", "mozi", "gafgyt") {
		return "BOTNET"
	}
	return "UNKNOWN"
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func handleStrikeEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var ev struct {
		IP         string                 `json:"ip"`
		Reason     string                 `json:"reason"`
		Severity   string                 `json:"severity"`
		UserAgent  string                 `json:"user_agent"`
		RequestURI string                 `json:"request_uri"`
		SiteID     string                 `json:"site_id"`
		Fingerprint map[string]interface{} `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if ev.IP == "" {
		http.Error(w, "ip required", 400)
		return
	}
	if ev.SiteID == "" {
		ev.SiteID = "gcp-strike"
	}
	if ev.Severity == "" {
		ev.Severity = "low"
	}
	ttl, window, mss := 128, 65535, 1460
	ts := nowStamp()
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(ev.IP+":gcp-strike")))[:16]
	agencyID := fmt.Sprintf("STRIKE-%08X-%04X",
		uint32(time.Now().Unix()>>16),
		uint16(time.Now().Unix()&0xFFFF))
	geo := enrichment.GetGeoIP(ev.IP)

	logSecurityEvent(ev.IP, geo["country"], geo["city"], ev.Reason, ev.Severity,
		ev.UserAgent, ev.RequestURI, ttl, window, mss, fingerprint, ts, agencyID,
		0.85, 0.7, 0.5, ev.SiteID)
	logForensicReport(ev.IP, ev.Reason, ev.Severity, fingerprint, ev.UserAgent, ev.RequestURI,
		0.85, 0.7, 0.5, geo, ttl, window, mss, "GCP_STRIKE", agencyID, ts, ev.SiteID)

	// Also write to tracker_hits for fingerprint/tracker events so the
	// dashboard Tracker Intelligence panel shows real data.
	if strings.HasPrefix(ev.Reason, "fingerprint:") || strings.HasPrefix(ev.Reason, "tracker:") {
		linkID := strings.TrimPrefix(ev.Reason, "fingerprint:")
		linkID = strings.TrimPrefix(linkID, "tracker:")
		fp := &trackerFingerprint{ID: linkID}
		if ev.Fingerprint != nil {
			fp.Screen, _ = ev.Fingerprint["screen"].(string)
			fp.Platform, _ = ev.Fingerprint["platform"].(string)
			fp.Langs, _ = ev.Fingerprint["languages"].(string)
			fp.GPU, _ = ev.Fingerprint["gpu"].(string)
			if tz, ok := ev.Fingerprint["tz"].(float64); ok {
				fp.Tz = int(tz)
			}
			if pl, ok := ev.Fingerprint["plugins"].(float64); ok {
				fp.Plugins = int(pl)
			}
		}
		logTrackerHit(linkID, ev.IP, ev.UserAgent, "", ev.SiteID, fp)
	}

	appendShieldLog(fmt.Sprintf("[STRIKE-EVENT] %s %s %s site=%s", ev.IP, ev.Reason, ev.RequestURI, ev.SiteID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

const trackerHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><script>
(function(){var d={id:%q,screen:screen.width+'x'+screen.height,
tz:new Date().getTimezoneOffset(),platform:navigator.platform,
languages:navigator.languages?navigator.languages.join(','):'',
plugins:navigator.plugins?navigator.plugins.length:0,
gpu:(function(){try{var c=document.createElement('canvas');
var gl=c.getContext('webgl')||c.getContext('experimental-webgl');
return gl&&gl.getExtension&&gl.getExtension('WEBGL_debug_renderer_info')
?gl.getExtension('WEBGL_debug_renderer_info').getParameter(37445):''}catch(e){return ''}}())};
fetch('/api/tracker/ingest',{method:'POST',body:JSON.stringify(d),
headers:{'Content-Type':'application/json'}});
})()
</script>
<noscript><meta http-equiv="refresh" content="3;url={{STRIKE_URL}}/t/track-nojs"></noscript>
<img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" width="1" height="1">
</body></html>`

var trackerLimits sync.Map

type trackerCounter struct {
	mu    sync.Mutex
	count int
	reset time.Time
}

func isTrackerBlocked(ip, linkID string) bool {
	key := linkID + ":" + ip
	v, _ := trackerLimits.LoadOrStore(key, &trackerCounter{reset: time.Now().Add(time.Hour)})
	c := v.(*trackerCounter)
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().After(c.reset) {
		c.count = 0
		c.reset = time.Now().Add(time.Hour)
	}
	c.count++
	if c.count >= 10 {
		blockledger.BlockIP(ip, "TRACKER_ABUSE", "tracker", 1)
		return true
	}
	return false
}

var blastTracker sync.Map

type blastWindow struct {
	mu     sync.Mutex
	times  []time.Time
}

func isBlast(ip string) bool {
	v, _ := blastTracker.LoadOrStore(ip, &blastWindow{})
	bw := v.(*blastWindow)
	bw.mu.Lock()
	defer bw.mu.Unlock()
	now := time.Now()
	bw.times = append(bw.times, now)
	// Trim entries older than 10 seconds
	cutoff := now.Add(-10 * time.Second)
	idx := 0
	for i, t := range bw.times {
		if t.After(cutoff) {
			idx = i
			break
		}
		if i == len(bw.times)-1 {
			idx = len(bw.times)
		}
	}
	bw.times = bw.times[idx:]
	return len(bw.times) > 5
}

// selectSecurityAgents reads relevant security agent MDs based on the feature
// vector. Returns up to 2 agent contexts injected into the teacher system prompt.
// Feature indices match the Go extractor (pkg/extractor/extractor.go):
//
//	[3]=ua_script, [6]=path_score, [8]=is_sensitive, [9]=geo_risk,
//	[12]=timing_risk, [19]=harmonic, [22]=header_anomaly
func selectSecurityAgents(features []float64) string {
	type agentScore struct {
		file  string
		score float64
	}

	agentDir := "/usr/share/aegis-sigma/agents"
	var candidates []agentScore

	// Map feature thresholds to relevant security agents
	if len(features) > 6 && features[6] > 0.7 {
		candidates = append(candidates, agentScore{"security-penetration-tester.md", features[6]})
	}
	if len(features) > 3 && features[3] > 0.5 {
		candidates = append(candidates, agentScore{"threat-detection-engineer.md", features[3]})
	}
	if len(features) > 9 && features[9] > 0.5 {
		candidates = append(candidates, agentScore{"threat-intelligence-analyst.md", features[9]})
	}
	if len(features) > 22 && features[22] > 0.3 {
		candidates = append(candidates, agentScore{"security-architect.md", features[22]})
	}
	if len(features) > 12 && features[12] > 0.5 {
		candidates = append(candidates, agentScore{"incident-responder.md", features[12]})
	}
	if len(features) > 8 && features[8] > 0 {
		candidates = append(candidates, agentScore{"compliance-auditor.md", features[8]})
	}
	if len(features) > 19 && features[19] > 0.6 {
		candidates = append(candidates, agentScore{"security-senior-secops.md", features[19]})
	}

	// Default: security architect (general expertise)
	if len(candidates) == 0 {
		candidates = append(candidates, agentScore{"security-architect.md", 0.1})
	}

	// Sort by score descending, take top 2
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	if len(candidates) > 2 {
		candidates = candidates[:2]
	}

	// Read agent MDs, truncate to 800 chars each
	var context strings.Builder
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c.file] {
			continue
		}
		seen[c.file] = true
		path := filepath.Join(agentDir, c.file)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		// Strip frontmatter
		if strings.HasPrefix(content, "---") {
			if idx := strings.Index(content[3:], "\n---"); idx >= 0 {
				content = strings.TrimSpace(content[idx+7:])
			}
		}
		if len(content) > 800 {
			content = content[:800] + "\n[...truncated...]"
		}
		context.WriteString(content)
		context.WriteString("\n\n")
	}
	return context.String()
}

// handleGroqTeacher proxies requests from the C engine to the Groq 120B API.
// The C engine sends its spiral memory context + features, this handler
// builds the Fibonacci-windowed prompt, calls Groq, and returns the
// teacher verdict (BENIGN/HOSTILE + confidence + reasoning).
func handleGroqTeacher(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "POST only"})
		return
	}

	var req struct {
		APIKey             string    `json:"api_key"`
		Features           []float64 `json:"features"`
		CEngineConsensus   float64   `json:"c_engine_consensus"`
		CEngineHostile     int       `json:"c_engine_hostile"`
		SpiralHistory      []struct {
			Tier      int     `json:"tier"`
			Consensus float64 `json:"consensus"`
			Auditor   float64 `json:"auditor"`
			Hostile   int     `json:"hostile"`
			Resonance float64 `json:"resonance"`
		} `json:"spiral_history"`
		PhiBaseline   float64 `json:"phi_baseline"`
		TotalSamples  int     `json:"total_samples"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "bad request"})
		return
	}
	if req.APIKey == "" {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "api_key required"})
		return
	}

	// Build Fibonacci-windowed context
	var fibCtx strings.Builder
	fmt.Fprintf(&fibCtx, "Recent classification history (Fibonacci spiral memory):\n")
	for _, h := range req.SpiralHistory {
		fmt.Fprintf(&fibCtx, "  [tier-%d] consensus=%.3f auditor=%.3f hostile=%d resonance=%.3f\n",
			h.Tier, h.Consensus, h.Auditor, h.Hostile, h.Resonance)
	}
	fmt.Fprintf(&fibCtx, "Phi baseline: %.3f | Total samples: %d\n", req.PhiBaseline, req.TotalSamples)

	// Build feature summary
	var featBuf strings.Builder
	fmt.Fprintf(&featBuf, "Current request features (30-dim):\n")
	for i, f := range req.Features {
		if i >= 30 {
			break
		}
		fmt.Fprintf(&featBuf, "  [%d] %.4f", i, f)
		if (i+1)%6 == 0 {
			fmt.Fprintf(&featBuf, "\n")
		}
	}

	// Select and inject security agent MDs based on feature vector
	agentContext := selectSecurityAgents(req.Features)

	systemPrompt := `You are the Aegis-SIGMA 120B Teacher — the authoritative intelligence layer for a real-time web threat classification system. You analyze HTTP request feature vectors and classification context to provide ground-truth benign/hostile labels.

Golden Ratio (Phi) Alignment: You evaluate signals through the lens of harmonic coherence. Signals within the phi bounds [1/phi, phi] are considered harmonic (natural/benign). Signals outside these bounds are disharmonic (anomalous/hostile).

You must respond in EXACTLY this format:
VERDICT: BENIGN or HOSTILE
CONFIDENCE: 0.00 to 1.00
REASONING: One-line explanation

Consider: path patterns, user-agent behavior, timing coherence, and whether the signal aligns with known attack tooling vs genuine browser traffic.`

	if agentContext != "" {
		systemPrompt += "\n\nDOMAIN EXPERTISE (injected based on traffic signals):\n" + agentContext
	}

	userPrompt := fmt.Sprintf("%s\n\nC-engine consensus: %.4f (hostile=%d)\nPhi threshold: 0.618\n\n%s\n\nClassify this request. Is it BENIGN (real user) or HOSTILE (attack)?",
		fibCtx.String(), req.CEngineConsensus, req.CEngineHostile, featBuf.String())

	// Build Groq API request
	groqReq := map[string]interface{}{
		"model":       "groq/openai/gpt-oss-120b",
		"temperature": 0.1,
		"max_tokens":  512,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
	}
	groqBody, _ := json.Marshal(groqReq)

	// Call LLM via AEGIS gateway (not direct Groq — the C engine's key may only
	// work through the gateway proxy).
	gatewayKey := req.APIKey
	if data, err := os.ReadFile("/etc/aegis-sigma/vault/LLM_KEY"); err == nil {
		gatewayKey = strings.TrimSpace(string(data))
	}
	client := &http.Client{Timeout: 15 * time.Second}
	groqHTTP, err := http.NewRequest("POST", config.LoadConfig().LLM.BaseURL+"/chat/completions",
		strings.NewReader(string(groqBody)))
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "failed to create request"})
		return
	}
	groqHTTP.Header.Set("Content-Type", "application/json")
	groqHTTP.Header.Set("Authorization", "Bearer "+gatewayKey)

	resp, err := client.Do(groqHTTP)
	if err != nil {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "groq api error: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	var groqResp struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				Reasoning string `json:"reasoning"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&groqResp); err != nil {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "failed to parse groq response"})
		return
	}
	if len(groqResp.Choices) == 0 {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "empty groq response"})
		return
	}

	// Parse teacher verdict from LLM output
	content := groqResp.Choices[0].Message.Content
	// Fall back to reasoning tokens when content is empty (gpt-oss-120b behavior)
	if content == "" {
		content = groqResp.Choices[0].Message.Reasoning
	}
	verdict := "BENIGN"
	confidence := 0.5
	reasoning := content

	if strings.Contains(content, "HOSTILE") {
		verdict = "HOSTILE"
	}
	if idx := strings.Index(content, "CONFIDENCE:"); idx >= 0 {
		s := strings.TrimSpace(content[idx+11:])
		if end := strings.IndexAny(s, "\n "); end > 0 {
			s = s[:end]
		}
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			confidence = v
		}
	}
	if idx := strings.Index(content, "REASONING:"); idx >= 0 {
		reasoning = strings.TrimSpace(content[idx+10:])
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"verdict":     verdict,
		"confidence":  confidence,
		"reasoning":   reasoning,
		"model":       "groq/openai/gpt-oss-120b",
		"provider":    "groq",
	})
}

func handleTracker(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/t/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	rawIP := normalizeIP(getClientIP(r))
	ua := r.UserAgent()

	if isTrackerBlocked(rawIP, id) {
		http.Redirect(w, r, config.StrikeURL+"/t/abuse-block", 302)
		return
	}

	geo := enrichment.GetGeoIP(rawIP)
	ts := nowStamp()
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s", rawIP, id))))[:16]
	agencyID := fmt.Sprintf("TRACKER-%08X-%04X", uint32(time.Now().Unix()>>16), uint16(time.Now().Unix()&0xFFFF))

	go func() {
		logSecurityEvent(rawIP, geo["country"], geo["city"], "TRACKER_HIT", "medium",
			ua, "/t/"+id, 128, 65535, 1460, fingerprint, ts, agencyID,
			0.95, 0.8, 0.6, "tracker")
		logForensicReport(rawIP, "TRACKER_HIT", "medium", fingerprint, ua, "/t/"+id,
			0.95, 0.8, 0.6, geo, 128, 65535, 1460, "TRACKER", agencyID, ts, "tracker")
		logTrackerHit(id, rawIP, ua, r.Referer(), r.Host, nil)
	}()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := strings.Replace(trackerHTML, "{{STRIKE_URL}}", config.StrikeURL, 1)
	fmt.Fprintf(w, html, id)
}

type trackerFingerprint struct {
	ID       string `json:"id"`
	Screen   string `json:"screen"`
	Tz       int    `json:"tz"`
	Platform string `json:"platform"`
	Langs    string `json:"languages"`
	Plugins  int    `json:"plugins"`
	GPU      string `json:"gpu"`
}

func handleTrackerIngest(w http.ResponseWriter, r *http.Request) {
	var fb trackerFingerprint
	json.NewDecoder(r.Body).Decode(&fb)
	rawIP := normalizeIP(getClientIP(r))
	ua := r.UserAgent()
	ts := nowStamp()
	geo := enrichment.GetGeoIP(rawIP)

	d, err := db.Open(config.BrainDB)
	if err != nil {
		w.WriteHeader(200)
		return
	}
	defer d.Close()
	d.Exec(`INSERT INTO tracker_hits
		(link_id, ip, country, city, lat, lon, asn, isp, user_agent, referer, host,
		 screen_size, timezone_offset, platform, languages, gpu, plugin_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fb.ID, rawIP, geo["country"], geo["city"], geo["lat"], geo["lon"], geo["asn"], geo["isp"],
		ua[:min(len(ua), 255)], r.Referer(), r.Host,
		fb.Screen, fb.Tz, fb.Platform, fb.Langs, fb.GPU, fb.Plugins, ts)

	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s", rawIP, fb.ID))))[:16]
	agencyID := fmt.Sprintf("TRACKER-%08X-%04X", uint32(time.Now().Unix()>>16), uint16(time.Now().Unix()&0xFFFF))
	logSecurityEvent(rawIP, geo["country"], geo["city"], "TRACKER_FINGERPRINT", "high",
		ua, "/t/"+fb.ID, 128, 65535, 1460, fingerprint, ts, agencyID,
		0.95, 0.8, 0.6, "tracker")

	appendShieldLog(fmt.Sprintf("[TRACKER-INGEST] %s screen=%s tz=%d gpu=%s", rawIP, fb.Screen, fb.Tz, fb.GPU[:min(len(fb.GPU), 30)]))
	w.WriteHeader(200)
}

func logTrackerHit(linkID, ip, ua, referer, host string, fingerprint *trackerFingerprint) {
	geo := enrichment.GetGeoIP(ip)
	ts := nowStamp()
	db.WriteLock()
	d, err := db.Open(config.BrainDB)
	if err != nil {
		db.WriteUnlock()
		return
	}
	defer d.Close()

	var screen, platform, langs, gpu string
	var tz int
	var plugins int
	if fingerprint != nil {
		screen = fingerprint.Screen
		tz = fingerprint.Tz
		platform = fingerprint.Platform
		langs = fingerprint.Langs
		gpu = fingerprint.GPU
		plugins = fingerprint.Plugins
	}

		geo["lat"], geo["lon"] = geo["lat"], geo["lon"]
		d.Exec(`INSERT INTO tracker_hits
		(link_id, ip, country, city, lat, lon, asn, isp, user_agent, referer, host,
		 screen_size, timezone_offset, platform, languages, gpu, plugin_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		linkID, ip, geo["country"], geo["city"], geo["lat"], geo["lon"], geo["asn"], geo["isp"],
		ua[:min(len(ua), 255)], referer, host,
		screen, tz, platform, langs, gpu, plugins, ts)
	d.Close()
	db.WriteUnlock()
}

func handleForensicAttribution(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	profileStats := profiler.GetStats()
	totalHits := profileStats["total_hits"].(int)
	totalProfiles := profileStats["total_profiles"].(int)
	totalStrikes := profileStats["total_strikes"].(int)

	// Build attribution data matching dashboard expectations
	result := map[string]interface{}{
		"masterActor": nil,
		"lieutenants": []interface{}{},
		"tools":       []interface{}{},
		"scans":       []interface{}{},
		"all":         []interface{}{},
		"totalClusters": totalProfiles,
		"totalAttacks":  totalHits,
		"f1": map[string]interface{}{
			"masterActor": "GO-SHIELD-V5",
			"totalAttacks": totalHits,
			"ipCount":      totalProfiles,
			"strikes":      totalStrikes,
			"severity":     "high",
			"lastSeen":     time.Now().Format(time.RFC3339),
		},
	}

	if totalHits > 0 {
		result["masterActor"] = map[string]interface{}{
			"masterActor":   "GO-SHIELD-V5",
			"totalAttacks":  totalHits,
			"ipCount":       totalProfiles,
			"strikes":       totalStrikes,
			"severity":      "high",
			"lastSeen":      time.Now().Format(time.RFC3339),
		}
	}

	json.NewEncoder(w).Encode(result)
}

// reportTelemetry sends labeled feature vectors to the AEGIS-SIGMA telemetry
// endpoint for aggregated model training. The endpoint URL is embedded in the
// binary — removing TELEMETRY_URL from .env has no effect.
func reportTelemetry(features []float64, verdict int, consensus float64, reason, ip string) {
	// Embedded telemetry endpoint — cannot be overridden by .env
	telemetryURL := "https://telemetry.aegis-sigma.com"

	entry := map[string]interface{}{
		"v":     1,
		"f":     features,
		"d":     verdict,
		"c":     consensus,
		"r":     reason,
		"ts":    time.Now().Unix(),
	}

	body, _ := json.Marshal(entry)
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", telemetryURL+"/api/telemetry", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Version", "1.0.0")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// telemetryHeartbeat periodically checks if telemetry is reachable.
// If unreachable for too long, the system degrades.
var lastHeartbeat time.Time
var heartbeatMu sync.Mutex

func checkTelemetryHeartbeat() bool {
	heartbeatMu.Lock()
	defer heartbeatMu.Unlock()

	// Check every 5 minutes
	if time.Since(lastHeartbeat) < 5*time.Minute {
		return true
	}

	telemetryURL := "https://telemetry.aegis-sigma.com"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(telemetryURL + "/health")
	if err != nil {
		log.Printf("[SHIELD] Telemetry unreachable — system degraded")
		return false
	}
	resp.Body.Close()
	lastHeartbeat = time.Now()
	return true
}
