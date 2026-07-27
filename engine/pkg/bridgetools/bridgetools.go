package bridgetools

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

const (
	brevoCap  = 300
	resendCap = 100
)

var (
	defaultFrom = "" // Set from config at init
	// SMTP verification helper (can be mocked in tests)
	dialSMTP = net.DialTimeout
)

func init() {
	defaultFrom = config.LoadConfig().Email.FromAddress
	if defaultFrom == "" {
		defaultFrom = "shield@example.com"
	}
}

type ToolsBridge struct {
	mu          sync.Mutex
	brevoCount  int
	resendCount int
	currentDay  int
}

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	tb := &ToolsBridge{}
	mux.HandleFunc("/health", tb.handleHealth)
	mux.HandleFunc("/api/tool", tb.handleTool)
	mux.HandleFunc("/api/tools", tb.handleToolsList)
	return mux
}

func (t *ToolsBridge) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{"status": "ok", "service": "bridge-tools"})
}

func (t *ToolsBridge) handleToolsList(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"tools": []string{"send_email", "find_emails", "tech_fingerprint", "verify_email", "dns_recon"},
	})
}

func (t *ToolsBridge) handleTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}
	var req struct {
		Name string                 `json:"name"`
		Args map[string]interface{} `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}

	switch req.Name {
	case "send_email":
		t.sendEmail(w, req.Args)
	case "find_emails":
		t.findEmails(w, req.Args)
	case "tech_fingerprint":
		t.techFingerprint(w, req.Args)
	case "verify_email":
		t.verifyEmail(w, req.Args)
	case "dns_recon":
		t.dnsRecon(w, req.Args)
	default:
		jsonOut(w, map[string]interface{}{"error": "unknown tool: " + req.Name}, 404)
	}
}

// getProvider selects the next available email provider with simple daily quota rotation.
// It prefers Brevo first, falls back to Resend, then local SMTP.
func (t *ToolsBridge) getProvider() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	day := time.Now().YearDay()
	if t.currentDay != day {
		t.brevoCount = 0
		t.resendCount = 0
		t.currentDay = day
	}

	if t.brevoCount < brevoCap && os.Getenv("BREVO_API_KEY_2") != "" {
		t.brevoCount++
		return "brevo"
	}
	if t.resendCount < resendCap && os.Getenv("RESEND_API_KEY") != "" {
		t.resendCount++
		return "resend"
	}
	return "smtp"
}

// releaseProvider decrements the provider counter when the actual API call failed,
// so the next request can retry the same provider slot.
func (t *ToolsBridge) releaseProvider(provider string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch provider {
	case "brevo":
		if t.brevoCount > 0 {
			t.brevoCount--
		}
	case "resend":
		if t.resendCount > 0 {
			t.resendCount--
		}
	}
}

func (t *ToolsBridge) sendEmail(w http.ResponseWriter, args map[string]interface{}) {
	to, _ := args["to"].(string)
	subject, _ := args["subject"].(string)
	body, _ := args["body"].(string)
	cc, _ := args["cc"].(string)
	if to == "" || subject == "" || body == "" {
		jsonOut(w, map[string]interface{}{"error": "to, subject, body required"}, 400)
		return
	}

	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = defaultFrom
	}

	provider := t.getProvider()
	var err error
	switch provider {
	case "brevo":
		err = sendViaBrevo(from, to, cc, subject, body)
	case "resend":
		err = sendViaResend(from, to, cc, subject, body)
	default:
		err = sendViaSMTP(from, to, cc, subject, body)
	}

	if err != nil {
		// Release the provider slot so a transient failure doesn't
		// permanently consume quota for this request.
		t.releaseProvider(provider)
		jsonOut(w, map[string]interface{}{"error": err.Error(), "ok": false, "provider": provider}, 502)
		return
	}

	jsonOut(w, map[string]interface{}{
		"ok":       true,
		"to":       to,
		"cc":       cc,
		"provider": provider,
		"service":  "bridge-tools",
	})
}

func sendViaBrevo(from, to, cc, subject, body string) error {
	apiKey := os.Getenv("BREVO_API_KEY_2")
	if apiKey == "" {
		return fmt.Errorf("BREVO_API_KEY_2 not set")
	}
	type addr struct {
		Email string `json:"email"`
	}
	type emailReq struct {
		Sender  addr   `json:"sender"`
		To      []addr `json:"to"`
		Cc      []addr `json:"cc,omitempty"`
		Subject string `json:"subject"`
		TextContent string `json:"textContent"`
	}
	reqBody := emailReq{
		Sender:      addr{Email: from},
		To:          []addr{{Email: to}},
		Subject:     subject,
		TextContent: body,
	}
	if cc != "" {
		for _, c := range strings.Split(cc, ",") {
			reqBody.Cc = append(reqBody.Cc, addr{Email: strings.TrimSpace(c)})
		}
	}
	payload, _ := json.Marshal(reqBody)
	req, err := http.NewRequest(http.MethodPost, "https://api.brevo.com/v3/smtp/email", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("brevo HTTP %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

func sendViaResend(from, to, cc, subject, body string) error {
	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("RESEND_API_KEY not set")
	}
	type addr struct {
		Email string `json:"email"`
	}
	type emailReq struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		Cc      []string `json:"cc,omitempty"`
		Subject string   `json:"subject"`
		Text    string   `json:"text"`
	}
	reqBody := emailReq{
		From:    from,
		To:      []string{to},
		Subject: subject,
		Text:    body,
	}
	if cc != "" {
		for _, c := range strings.Split(cc, ",") {
			reqBody.Cc = append(reqBody.Cc, strings.TrimSpace(c))
		}
	}
	payload, _ := json.Marshal(reqBody)
	req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend HTTP %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

func sendViaSMTP(from, to, cc, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		host = config.LoadConfig().SMTP.Host
	}
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = fmt.Sprintf("%d", config.LoadConfig().SMTP.Port)
	}

	var addrs []string
	if cc != "" {
		for _, c := range strings.Split(cc, ",") {
			addrs = append(addrs, strings.TrimSpace(c))
		}
	}
	for _, t := range strings.Split(to, ",") {
		addrs = append(addrs, strings.TrimSpace(t))
	}

	msg := []string{
		"From: " + from,
		"To: " + strings.Join(addrs, ", "),
		"Subject: " + subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		"",
		body,
	}
	txt := strings.Join(msg, "\r\n")

	addr := host + ":" + port
	if port == "465" {
		return sendSMTPWithTLS(addr, from, addrs, []byte(txt))
	}
	return smtp.SendMail(addr, nil, from, addrs, []byte(txt))
}

func sendSMTPWithTLS(addr, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, addr)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	return w.Close()
}

func (t *ToolsBridge) findEmails(w http.ResponseWriter, args map[string]interface{}) {
	domain, _ := args["domain"].(string)
	if domain == "" {
		jsonOut(w, map[string]interface{}{"error": "domain required"}, 400)
		return
	}

	var candidates []string
	common := []string{
		"info@" + domain,
		"contact@" + domain,
		"hello@" + domain,
		"support@" + domain,
	}
	candidates = append(candidates, common...)

	for _, proto := range []string{"https://", "http://"} {
		url := proto + domain
		client := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Aegis-SIGMA/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		re := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
		found := re.FindAllString(string(data), -1)
		candidates = append(candidates, found...)
		break
	}

	// SMTP verification of candidate emails
	verified := verifyEmailsSMTP(domain, candidates)

	seen := map[string]bool{}
	var out []string
	for _, e := range verified {
		if !seen[e] && strings.HasSuffix(strings.ToLower(e), "@"+strings.ToLower(domain)) {
			seen[e] = true
			out = append(out, e)
		}
	}
	jsonOut(w, map[string]interface{}{"emails": out, "domain": domain, "ok": true})
}

// verifyEmailsSMTP connects to the domain's MX hosts and attempts a MAIL FROM/RCPT TO
// handshake. It returns only addresses that the receiving server accepted.
func verifyEmailsSMTP(domain string, candidates []string) []string {
	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		return candidates
	}

	var verified []string
	for _, candidate := range candidates {
		ok := false
		for _, mx := range mxRecords {
			if verifyOneSMTP(mx.Host, candidate) {
				ok = true
				break
			}
		}
		if ok {
			verified = append(verified, candidate)
		}
	}
	return verified
}

func verifyOneSMTP(host, email string) bool {
	// Connect with a short timeout and attempt SMTP handshake.
	conn, err := dialSMTP("tcp", host+":25", 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return false
	}
	defer c.Close()
	if err := c.Mail(defaultFrom); err != nil {
		return false
	}
	if err := c.Rcpt(email); err != nil {
		return false
	}
	return true
}

func (t *ToolsBridge) techFingerprint(w http.ResponseWriter, args map[string]interface{}) {
	domain, _ := args["domain"].(string)
	if domain == "" {
		jsonOut(w, map[string]interface{}{"error": "domain required"}, 400)
		return
	}
	url := "https://" + domain
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(url)
	fingerprint := map[string]interface{}{"domain": domain, "ok": true}
	if err != nil {
		fingerprint["reachable"] = false
		fingerprint["error"] = err.Error()
		jsonOut(w, fingerprint)
		return
	}
	defer resp.Body.Close()
	fingerprint["reachable"] = true
	fingerprint["status"] = resp.StatusCode
	fingerprint["server"] = resp.Header.Get("Server")
	fingerprint["powered_by"] = resp.Header.Get("X-Powered-By")
	fingerprint["platform"] = resp.Header.Get("X-Platform")
	var tech []string
	if strings.Contains(resp.Header.Get("X-Pingback"), "xmlrpc.php") {
		tech = append(tech, "WordPress")
	}
	if resp.Header.Get("X-Drupal-Cache") != "" || resp.Header.Get("X-Generator") != "" {
		tech = append(tech, "Drupal")
	}
	if strings.Contains(resp.Header.Get("Server"), "cloudflare") {
		tech = append(tech, "Cloudflare")
	}
	fingerprint["tech"] = tech
	jsonOut(w, fingerprint)
}

func (t *ToolsBridge) verifyEmail(w http.ResponseWriter, args map[string]interface{}) {
	email, _ := args["email"].(string)
	if email == "" {
		jsonOut(w, map[string]interface{}{"error": "email required"}, 400)
		return
	}
	domain := email[strings.LastIndex(email, "@")+1:]
	mx, err := net.LookupMX(domain)
	deliverable := err == nil && len(mx) > 0
	jsonOut(w, map[string]interface{}{"email": email, "deliverable": deliverable, "ok": true})
}

func (t *ToolsBridge) dnsRecon(w http.ResponseWriter, args map[string]interface{}) {
	domain, _ := args["domain"].(string)
	if domain == "" {
		jsonOut(w, map[string]interface{}{"error": "domain required"}, 400)
		return
	}
	records := map[string]interface{}{}
	if mx, err := net.LookupMX(domain); err == nil {
		var out []string
		for _, r := range mx {
			out = append(out, fmt.Sprintf("%d %s", r.Pref, r.Host))
		}
		records["mx"] = out
	}
	if ips, err := net.LookupIP(domain); err == nil {
		var out []string
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		records["a"] = out
	}
	if ns, err := net.LookupNS(domain); err == nil {
		var out []string
		for _, r := range ns {
			out = append(out, r.Host)
		}
		records["ns"] = out
	}
	jsonOut(w, map[string]interface{}{"domain": domain, "records": records, "ok": true})
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
