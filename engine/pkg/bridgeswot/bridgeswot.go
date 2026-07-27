package bridgeswot

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SWOTBridge struct{}

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	s := &SWOTBridge{}
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/swot", s.handleSWOT)
	mux.HandleFunc("/api/swot/generate", s.handleSWOT)
	return mux
}

func (s *SWOTBridge) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{"status": "ok", "service": "bridge-swot"})
}

func (s *SWOTBridge) handleSWOT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		jsonOut(w, map[string]interface{}{"error": "domain required"}, 400)
		return
	}
	report := generateSWOT(domain)
	jsonOut(w, report)
}

func generateSWOT(domain string) map[string]interface{} {
	url := "https://" + domain
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url)
	reachable := err == nil
	status := 0
	server := ""
	httpsOk := false
	if resp != nil {
		status = resp.StatusCode
		server = resp.Header.Get("Server")
		httpsOk = true
		resp.Body.Close()
	}

	strengths := []string{"Online presence confirmed"}
	weaknesses := []string{}
	opportunities := []string{"Security posture review", "Compliance audit"}
	threats := []string{"Public exposure", "Automated scanners"}

	if !reachable {
		weaknesses = append(weaknesses, "Site unreachable over HTTPS")
		threats = append(threats, "Possible outage or block")
	}
	if status >= 400 {
		weaknesses = append(weaknesses, fmt.Sprintf("HTTP status %d", status))
	}
	if !httpsOk {
		weaknesses = append(weaknesses, "HTTPS not available")
		threats = append(threats, "Man-in-the-middle risk")
	}
	if server != "" {
		strengths = append(strengths, "Server technology identifiable: "+server)
	}

	score := 50
	if httpsOk {
		score += 20
	}
	if reachable {
		score += 10
	}
	if status >= 200 && status < 400 {
		score += 10
	}
	if score > 100 {
		score = 100
	}

	return map[string]interface{}{
		"domain":      domain,
		"ok":          true,
		"score":       score,
		"reachable":   reachable,
		"status":      status,
		"https":       httpsOk,
		"server":      server,
		"strengths":   strengths,
		"weaknesses":  weaknesses,
		"opportunities": opportunities,
		"threats":     threats,
		"summary":     fmt.Sprintf("%s scored %d/100. HTTPS=%v Reachable=%v", domain, score, httpsOk, reachable),
	}
}

func jsonOut(w http.ResponseWriter, v interface{}, code ...int) {
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if len(code) > 0 {
		status = code[0]
	}
	w.WriteHeader(status)
	data, _ := json.Marshal(v)
	w.Write(data)
}
