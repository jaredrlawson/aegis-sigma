package bridgemain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

// EmailSender handles sending emails via Brevo.
type EmailSender struct {
	APIKey     string
	FromEmail  string
	FromName   string
	HTTPClient *http.Client
}

// NewEmailSender creates an email sender from vault keys + config.
func NewEmailSender() *EmailSender {
	cfg := config.LoadConfig()
	return &EmailSender{
		APIKey:     readBrevoKey(),
		FromEmail:  cfg.Email.FromAddress,
		FromName:   cfg.Email.FromName,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func readBrevoKey() string {
	// Try primary key first
	data, err := os.ReadFile("/etc/aegis-sigma/vault/BREVO_API_KEY")
	if err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			return key
		}
	}
	// Fallback to secondary key
	data, err = os.ReadFile("/etc/aegis-sigma/vault/BREVO_API_KEY_2")
	if err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

// SendReport sends a clean report email (no call script) to the prospect.
func (e *EmailSender) SendReport(report Report) error {
	if e.APIKey == "" {
		return fmt.Errorf("Brevo API key not configured")
	}
	if report.Email == "" {
		return fmt.Errorf("no email address for %s", report.Domain)
	}

	subject := fmt.Sprintf("Security Assessment for %s", report.Domain)
	body := buildReportHTML(report)

	return e.send(report.Email, subject, body)
}

// SendQuote sends a quote email with Stripe checkout link.
func (e *EmailSender) SendQuote(quote Quote, checkoutURL string) error {
	if e.APIKey == "" {
		return fmt.Errorf("Brevo API key not configured")
	}
	if quote.Email == "" {
		return fmt.Errorf("no email address for %s", quote.Domain)
	}

	subject := fmt.Sprintf("Security Quote for %s", quote.Domain)
	body := buildQuoteHTML(quote, checkoutURL)

	return e.send(quote.Email, subject, body)
}

// send sends an email via Brevo API.
func (e *EmailSender) send(to, subject, htmlBody string) error {
	payload := map[string]interface{}{
		"sender": map[string]string{
			"name":  e.FromName,
			"email": e.FromEmail,
		},
		"to": []map[string]string{
			{"email": to},
		},
		"subject":     subject,
		"htmlContent": htmlBody,
	}

	jsonBody, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", "https://api.brevo.com/v3/smtp/email", bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("api-key", e.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("brevo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("brevo error %d: %s", resp.StatusCode, string(errBody))
	}

	log.Printf("[bridge] sent email to %s: %s", to, subject)
	return nil
}

// buildReportHTML generates a clean report email (no call script).
func buildReportHTML(r Report) string {
	var findingsHTML string
	for _, f := range r.Findings {
		color := "#50C878"
		if f.Severity >= 7 {
			color = "#ff4444"
		} else if f.Severity >= 4 {
			color = "#FF9800"
		}
		findingsHTML += fmt.Sprintf(`<tr>
<td style="padding:8px;border-bottom:1px solid #222;color:%s;font-weight:700;">%s/%d</td>
<td style="padding:8px;border-bottom:1px solid #222;">%s</td>
</tr>`, color, f.Category, f.Severity, f.Finding)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0B0B0D;color:#e6edf3;font-family:Inter,system-ui,sans-serif;">
<div style="max-width:600px;margin:0 auto;padding:30px;">
<div style="text-align:center;margin-bottom:24px;">
<h1 style="color:#00E5FF;font-size:20px;margin:0;">AEGIS-SIGMA Security</h1>
<p style="color:#8b949e;font-size:12px;">Security Assessment Report</p>
</div>

<div style="background:#121216;border:1px solid rgba(0,229,255,0.15);border-radius:12px;padding:24px;margin-bottom:20px;">
<h2 style="color:#00E5FF;font-size:16px;margin:0 0 12px 0;">Assessment Summary</h2>
<table style="width:100%%;font-size:13px;">
<tr><td style="color:#8b949e;padding:4px 0;">Domain</td><td style="text-align:right;">%s</td></tr>
<tr><td style="color:#8b949e;padding:4px 0;">Risk Level</td><td style="text-align:right;color:%s;font-weight:700;">%s</td></tr>
<tr><td style="color:#8b949e;padding:4px 0;">Security Score</td><td style="text-align:right;">%d/100</td></tr>
<tr><td style="color:#8b949e;padding:4px 0;">Issues Found</td><td style="text-align:right;">%d</td></tr>
</table>
</div>

<div style="background:#121216;border:1px solid rgba(0,229,255,0.15);border-radius:12px;padding:24px;margin-bottom:20px;">
<h2 style="color:#00E5FF;font-size:16px;margin:0 0 12px 0;">Findings</h2>
<table style="width:100%%;border-collapse:collapse;font-size:13px;">
<tr style="border-bottom:2px solid #333;">
<th style="text-align:left;padding:8px;color:#8b949e;">Category</th>
<th style="text-align:left;padding:8px;color:#8b949e;">Finding</th>
</tr>
%s</table>
</div>

<div style="background:#121216;border:1px solid rgba(0,229,255,0.15);border-radius:12px;padding:24px;margin-bottom:20px;">
<h2 style="color:#00E5FF;font-size:16px;margin:0 0 12px 0;">Recommendations</h2>
<p style="font-size:13px;color:#c9d1d9;line-height:1.6;">Based on our assessment, we recommend addressing the identified issues to improve your security posture. Contact us for a detailed remediation plan and pricing.</p>
</div>

<div style="text-align:center;padding:20px 0;">
<p style="color:#8b949e;font-size:12px;">AEGIS-SIGMA Security</p>
<p style="color:#8b949e;font-size:11px;">If you prefer not to receive future emails, reply unsubscribe</p>
</div>
</div>
</body>
</html>`, r.Domain, riskColor(r.RiskLevel), r.RiskLevel, r.Score, len(r.Findings), findingsHTML)
}

// buildQuoteHTML generates a quote email with Stripe checkout link.
func buildQuoteHTML(q Quote, checkoutURL string) string {
	var itemsHTML string
	for _, item := range q.Items {
		itemsHTML += fmt.Sprintf(`<tr>
<td style="padding:8px;border-bottom:1px solid #222;">%s</td>
<td style="padding:8px;border-bottom:1px solid #222;color:#8b949e;font-size:12px;">%s</td>
<td style="padding:8px;border-bottom:1px solid #222;text-align:right;font-weight:700;">$%d</td>
</tr>`, item.Service, item.Description, item.Price/100)
	}

	ctaHTML := ""
	if checkoutURL != "" {
		ctaHTML = fmt.Sprintf(`<div style="text-align:center;margin:20px 0;">
<a href="%s" style="display:inline-block;background:linear-gradient(135deg,#00E5FF,#9966CC);color:#000;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:14px;">Pay Now — $%d</a>
</div>`, checkoutURL, q.Total/100)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0B0B0D;color:#e6edf3;font-family:Inter,system-ui,sans-serif;">
<div style="max-width:600px;margin:0 auto;padding:30px;">
<div style="text-align:center;margin-bottom:24px;">
<h1 style="color:#00E5FF;font-size:20px;margin:0;">AEGIS-SIGMA Security</h1>
<p style="color:#8b949e;font-size:12px;">Security Quote</p>
</div>

<div style="background:#121216;border:1px solid rgba(0,229,255,0.15);border-radius:12px;padding:24px;margin-bottom:20px;">
<h2 style="color:#00E5FF;font-size:16px;margin:0 0 12px 0;">Quote for %s</h2>
<table style="width:100%%;border-collapse:collapse;font-size:13px;">
<tr style="border-bottom:2px solid #333;">
<th style="text-align:left;padding:8px;color:#8b949e;">Service</th>
<th style="text-align:left;padding:8px;color:#8b949e;">Description</th>
<th style="text-align:right;padding:8px;color:#8b949e;">Price</th>
</tr>
%s
<tr style="border-top:2px solid #333;">
<td colspan="2" style="padding:8px;font-weight:700;">Total</td>
<td style="padding:8px;text-align:right;font-weight:700;font-size:16px;color:#00E5FF;">$%d</td>
</tr>
</table>
</div>

%s

<div style="background:#121216;border:1px solid rgba(0,229,255,0.15);border-radius:12px;padding:24px;margin-bottom:20px;">
<h2 style="color:#00E5FF;font-size:16px;margin:0 0 12px 0;">What's Included</h2>
<ul style="font-size:13px;color:#c9d1d9;line-height:1.8;padding-left:20px;">
<li>Full security assessment and remediation</li>
<li>Progress updates throughout the process</li>
<li>30-day post-fix monitoring</li>
<li>Documentation and compliance reports</li>
</ul>
</div>

<div style="text-align:center;padding:20px 0;">
<p style="color:#8b949e;font-size:12px;">AEGIS-SIGMA Security</p>
<p style="color:#8b949e;font-size:11px;">If you prefer not to receive future emails, reply unsubscribe</p>
</div>
</div>
</body>
</html>`, q.BusinessName, itemsHTML, q.Total/100, ctaHTML)
}

func riskColor(level string) string {
	switch level {
	case "Critical":
		return "#ff4444"
	case "High":
		return "#FF9800"
	case "Medium":
		return "#FFB74D"
	default:
		return "#50C878"
	}
}
