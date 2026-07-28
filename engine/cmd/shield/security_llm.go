package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

// SecurityLLMRequest is the input for security LLM endpoints.
type SecurityLLMRequest struct {
	Context  string `json:"context"`   // Additional context from dashboard
	LeadID   int    `json:"lead_id"`   // Optional lead ID for context
	Domain   string `json:"domain"`    // Optional domain for context
	TimeRange string `json:"time_range"` // "1h", "24h", "7d"
}

// SecurityLLMResponse is the output from security LLM endpoints.
type SecurityLLMResponse struct {
	Task    string `json:"task"`
	Content string `json:"content"`
	Model   string `json:"model"`
	Cost    string `json:"cost"`
}

// callSecurityLLM calls DeepInfra API with agent expertise + context.
func callSecurityLLM(task, agentFile, prompt string) (string, error) {
	apiKey := config.ReadVault("LLM_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("LLM_KEY not configured in vault")
	}

	// Read agent MD for expertise context
	agentDir := "/usr/share/aegis-sigma/agents/security"
	agentContext := ""
	if agentFile != "" {
		data, err := os.ReadFile(agentDir + "/" + agentFile)
		if err == nil {
			content := string(data)
			if strings.HasPrefix(content, "---") {
				if idx := strings.Index(content[3:], "\n---"); idx >= 0 {
					content = strings.TrimSpace(content[idx+7:])
				}
			}
			if len(content) > 1500 {
				content = content[:1500] + "\n[...truncated...]"
			}
			agentContext = content
		}
	}

	// Build system prompt with agent expertise
	systemPrompt := "You are a cybersecurity expert. Provide detailed, actionable analysis."
	if agentContext != "" {
		systemPrompt += "\n\nDOMAIN EXPERTISE:\n" + agentContext
	}

	payload := map[string]interface{}{
		"model":  config.LoadConfig().LLM.ModelCallPrep,
		"temperature": 0.3,
		"max_tokens":  2000,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
	}
	body, _ := json.Marshal(payload)

	// Call DeepInfra via gateway
	gatewayURL := config.LoadConfig().LLM.BaseURL
	req, err := http.NewRequest("POST", gatewayURL+"/chat/completions",
		strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("LLM API error %d: %s", resp.StatusCode, string(errBody[:min(len(errBody), 200)]))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				Reasoning string `json:"reasoning"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parse error: %v", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}

	content := result.Choices[0].Message.Content
	if content == "" {
		content = result.Choices[0].Message.Reasoning
	}
	return content, nil
}

// getRecentEvents fetches recent security events from brain.sqlite for context.
func getRecentEvents(timeRange string) string {
	d, err := sql.Open("sqlite", config.BrainDB)
	if err != nil {
		return "No security events available"
	}
	defer d.Close()

	since := "datetime('now', '-1 hours')"
	switch timeRange {
	case "24h":
		since = "datetime('now', '-24 hours')"
	case "7d":
		since = "datetime('now', '-7 days')"
	}

	rows, err := d.Query(fmt.Sprintf(`
		SELECT ip, reason, severity, created_at
		FROM security_events
		WHERE created_at > %s
		ORDER BY created_at DESC
		LIMIT 50
	`, since))
	if err != nil {
		return "No security events available"
	}
	defer rows.Close()

	var events []string
	for rows.Next() {
		var ip, reason, severity, ts string
		if rows.Scan(&ip, &reason, &severity, &ts) == nil {
			events = append(events, fmt.Sprintf("[%s] %s from %s (%s)", ts, reason, ip, severity))
		}
	}
	if len(events) == 0 {
		return "No recent security events"
	}
	return strings.Join(events, "\n")
}

// getThreatLog fetches recent threat log entries.
func getThreatLog(timeRange string) string {
	d, err := sql.Open("sqlite", config.BrainDB)
	if err != nil {
		return "No threat data available"
	}
	defer d.Close()

	since := "datetime('now', '-1 hours')"
	switch timeRange {
	case "24h":
		since = "datetime('now', '-24 hours')"
	case "7d":
		since = "datetime('now', '-7 days')"
	}

	rows, err := d.Query(fmt.Sprintf(`
		SELECT threat_type, details, domain, created_at
		FROM threat_log
		WHERE created_at > %s
		ORDER BY created_at DESC
		LIMIT 30
	`, since))
	if err != nil {
		return "No threat data available"
	}
	defer rows.Close()

	var entries []string
	for rows.Next() {
		var ttype, details, domain, ts string
		if rows.Scan(&ttype, &details, &domain, &ts) == nil {
			entries = append(entries, fmt.Sprintf("[%s] %s on %s: %s", ts, ttype, domain, details))
		}
	}
	if len(entries) == 0 {
		return "No recent threat data"
	}
	return strings.Join(entries, "\n")
}

// ─── Incident Response ───────────────────────────────────────────────────────

func handleIncidentResponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "POST only"})
		return
	}

	var req SecurityLLMRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.TimeRange == "" {
		req.TimeRange = "24h"
	}

	events := getRecentEvents(req.TimeRange)
	prompt := fmt.Sprintf(`Write an incident response playbook for the following security events.

TIME RANGE: Last %s
RECENT EVENTS:
%s

ADDITIONAL CONTEXT: %s

Provide:
1. THREAT ASSESSMENT: Severity level (Critical/High/Medium/Low) with justification
2. IMMEDIATE ACTIONS: Step-by-step containment procedures (first 15 minutes)
3. INVESTIGATION: What to check, logs to review, IOCs to hunt
4. CONTAINMENT: Network isolation, account lockout, service shutdown decisions
5. ERADICATION: How to remove the threat
6. RECOVERY: Steps to restore normal operations
7. LESSONS LEARNED: What to prevent this in the future

Format as a structured playbook with numbered steps. Be specific and actionable.`, req.TimeRange, events, req.Context)

	content, err := callSecurityLLM("incident-response", "incident-responder.md", prompt)
	if err != nil {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(SecurityLLMResponse{
		Task:    "incident-response",
		Content: content,
		Model:   config.LoadConfig().LLM.ModelCallPrep,
		Cost:    "~$0.0001",
	})
}

// ─── Threat Intelligence ─────────────────────────────────────────────────────

func handleThreatIntel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "POST only"})
		return
	}

	var req SecurityLLMRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.TimeRange == "" {
		req.TimeRange = "24h"
	}

	events := getRecentEvents(req.TimeRange)
	threats := getThreatLog(req.TimeRange)
	prompt := fmt.Sprintf(`Analyze the following security data and produce a threat intelligence report.

TIME RANGE: Last %s
SECURITY EVENTS:
%s

THREAT LOG:
%s

ADDITIONAL CONTEXT: %s

Provide:
1. EXECUTIVE SUMMARY: Key findings in 2-3 sentences
2. THREAT ACTOR ANALYSIS: Likely attribution (bot networks, scanners, targeted attackers)
3. ATTACK PATTERNS: What techniques are being used (recon, exploitation, exfiltration)
4. GEOGRAPHIC DISTRIBUTION: Where attacks originate
5. TIMING PATTERNS: When attacks cluster (time of day, day of week)
6. INDICATORS OF COMPROMISE: Specific IPs, domains, signatures to block
7. RECOMMENDATIONS: Priority actions to improve defense

Format as a structured report with headers.`, req.TimeRange, events, threats, req.Context)

	content, err := callSecurityLLM("threat-intel", "threat-intelligence-analyst.md", prompt)
	if err != nil {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(SecurityLLMResponse{
		Task:    "threat-intel",
		Content: content,
		Model:   config.LoadConfig().LLM.ModelCallPrep,
		Cost:    "~$0.0001",
	})
}

// ─── Compliance Check ────────────────────────────────────────────────────────

func handleComplianceCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "POST only"})
		return
	}

	var req SecurityLLMRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.TimeRange == "" {
		req.TimeRange = "24h"
	}

	events := getRecentEvents(req.TimeRange)
	prompt := fmt.Sprintf(`Perform a compliance assessment based on the following security events.

TIME RANGE: Last %s
SECURITY EVENTS:
%s

ADDITIONAL CONTEXT: %s

Evaluate compliance against these frameworks:
1. SOC 2 Type II: Security, Availability, Processing Integrity, Confidentiality, Privacy
2. HIPAA: Administrative, Physical, Technical Safeguards
3. PCI DSS: Network Security, Access Control, Monitoring, Policy
4. NIST CSF: Identify, Protect, Detect, Respond, Recover

For each framework:
- COMPLIANCE STATUS: Compliant / Partially Compliant / Non-Compliant
- GAPS: Specific areas where the current setup falls short
- EVIDENCE: Which events support or contradict compliance
- REMEDIATION: Prioritized steps to achieve compliance
- RISK SCORE: 1-10 with justification

Format as a structured compliance report.`, req.TimeRange, events, req.Context)

	content, err := callSecurityLLM("compliance-check", "compliance-auditor.md", prompt)
	if err != nil {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(SecurityLLMResponse{
		Task:    "compliance-check",
		Content: content,
		Model:   config.LoadConfig().LLM.ModelCallPrep,
		Cost:    "~$0.0001",
	})
}

// ─── Audit Summary ───────────────────────────────────────────────────────────

func handleAuditSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "POST only"})
		return
	}

	var req SecurityLLMRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.TimeRange == "" {
		req.TimeRange = "24h"
	}

	events := getRecentEvents(req.TimeRange)
	threats := getThreatLog(req.TimeRange)
	prompt := fmt.Sprintf(`Write a comprehensive security audit summary for the following period.

TIME RANGE: Last %s
SECURITY EVENTS:
%s

THREAT LOG:
%s

ADDITIONAL CONTEXT: %s

Provide:
1. EXECUTIVE SUMMARY: 3-5 sentence overview of security posture
2. KEY METRICS:
   - Total events analyzed
   - Hostile vs benign ratio
   - Average threat severity
   - Mean time to detection
3. CRITICAL FINDINGS: Top 3 issues requiring immediate attention
4. DEFENSE EFFECTIVENESS: How well current controls are working
5. TREND ANALYSIS: Are things getting better or worse?
6. RESOURCE ALLOCATION: Where to focus security efforts
7. BUDGET RECOMMENDATIONS: Cost-effective improvements

Format as a professional audit report suitable for executive review.`, req.TimeRange, events, threats, req.Context)

	content, err := callSecurityLLM("audit-summary", "security-senior-secops.md", prompt)
	if err != nil {
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(SecurityLLMResponse{
		Task:    "audit-summary",
		Content: content,
		Model:   config.LoadConfig().LLM.ModelCallPrep,
		Cost:    "~$0.0001",
	})
}
