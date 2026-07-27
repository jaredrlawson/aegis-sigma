package bridgemain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

// handleCallPrep generates a tailored phone-call script via gpt-oss-120b.
// The model sees the prospect's scan findings, business data, and pricing,
// then writes a realistic cold-call script — opening, objections, close.
func (b *BridgeMain) handleCallPrep(w http.ResponseWriter, r *http.Request) {
	leadID := r.URL.Query().Get("lead_id")
	if leadID == "" {
		jsonOut(w, map[string]interface{}{"error": "lead_id required"}, 400)
		return
	}

	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	var id, score int
	var d, name, email, city, state, bizType, notes, phone, address string
	err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''),
		COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''),
		score, COALESCE(target_business,''), COALESCE(notes,'')
		FROM leads WHERE id = ?`, leadID).Scan(
		&id, &d, &name, &email, &phone, &address, &city, &state, &score, &bizType, &notes)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
		return
	}

	report := BuildReport(d, name, city, state, bizType, score, notes)
	quote := GeneratePricing(report, email)

	prompt := buildCallPrepPrompt(report, quote, phone, address)

	script, err := callLLM120B(prompt)
	if err != nil {
		jsonOut(w, map[string]interface{}{
			"error":   "llm failed",
			"details": err.Error(),
			"prompt":  prompt,
		}, 502)
		return
	}

	jsonOut(w, map[string]interface{}{
		"lead_id":      id,
		"domain":      d,
		"script":      script,
		"risk_level":  report.RiskLevel,
		"score":       report.Score,
		"findings":    report.Findings,
		"top_finding": topFinding(report),
		"total_quote": quoteTotal(quote),
		"phone":       phone,
	})
}

func buildCallPrepPrompt(report Report, quote Quote, phone, address string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are a senior B2B sales coach writing a cold-call script for Jared Lawson at AEGIS-SIGMA Security.\n\n")
	fmt.Fprintf(&b, "PROSPECT DATA:\n")
	fmt.Fprintf(&b, "- Business: %s\n", report.BusinessName)
	fmt.Fprintf(&b, "- Domain: %s\n", report.Domain)
	fmt.Fprintf(&b, "- City: %s, %s\n", report.City, report.State)
	fmt.Fprintf(&b, "- Industry: %s\n", report.BusinessType)
	fmt.Fprintf(&b, "- Phone: %s\n", phone)
	fmt.Fprintf(&b, "- Address: %s\n", address)
	fmt.Fprintf(&b, "- Risk Level: %s (score %d/100)\n\n", report.RiskLevel, report.Score)

	if len(report.Findings) == 0 {
		b.WriteString("SCAN STATUS: No scan has run on this domain yet.\n\n")
	} else {
		b.WriteString("SCAN FINDINGS (ranked by severity):\n")
		for i, f := range report.Findings {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&b, "- [%s/%d] %s\n", f.Category, f.Severity, f.Finding)
		}
		b.WriteString("\n")
	}

	total := quoteTotal(quote)
	if total > 0 {
		fmt.Fprintf(&b, "SUGGESTED RETAIL PRICING: $%.2f total (line items: %d)\n\n", float64(total)/100, len(quote.Items))
	}

	b.WriteString("Write a REALISTIC cold-call script (English only). Frame issues as performance/revenue opportunities, not security fear.\n\n")
	b.WriteString("Format:\n\n")
	b.WriteString("OPENING: <15-25 word hook using their business name + specific scan finding framed as opportunity>\n\n")
	b.WriteString("VALUE props: 3 bullet points linking specific finding to revenue impact\n\n")
	b.WriteString("OBJECTION HANDLINGS:\n")
	b.WriteString("1. \"Not interested\" → <response>\n")
	b.WriteString("2. \"Send me an email\" → <response>\n")
	b.WriteString("3. \"Too expensive\" → <response referencing specific finding + entry price point>\n\n")
	b.WriteString("CLOSE: <assumptive, statement-form, offers specific next step + 2 date options>\n\n")
	b.WriteString("Keep it under 250 words. No placeholders — use real business name and domain. No pricing wall.\n")
	return b.String()
}

func callLLM120B(prompt string) (string, error) {
	key := os.Getenv("LLM_KEY")
	if key == "" {
		data, err := os.ReadFile("/etc/aegis-sigma/vault/LLM_KEY")
		if err != nil {
			return "", fmt.Errorf("no LLM key: %v", err)
		}
		key = strings.TrimSpace(string(data))
	}

	body := map[string]interface{}{
		"model": "groq/openai/gpt-oss-120b",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"stream":           false,
		"max_tokens":       4000,
		"temperature":      0.7,
		"reasoning_effort": "low",
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", config.LoadConfig().LLM.BaseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("llm http %d: %s", resp.StatusCode, string(raw))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				Reasoning string `json:"reasoning"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		clean := extractFirstJSON(raw)
		if clean == nil {
			return "", fmt.Errorf("decode: %v (raw head: %s)", err, truncate(raw, 300))
		}
		if err := json.Unmarshal(clean, &parsed); err != nil {
			return "", fmt.Errorf("decode-clean: %v", err)
		}
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("empty content (finish_reason=%s) — likely max_tokens consumed by reasoning", parsed.Choices[0].FinishReason)
	}
	return content, nil
}

// extractFirstJSON defends against SSE-style "data: {...}\ndata: {...}" leaks.
func extractFirstJSON(raw []byte) []byte {
	s := string(raw)
	for strings.HasPrefix(s, "data: ") {
		s = strings.TrimPrefix(s, "data: ")
	}
	start := strings.Index(s, "{")
	for start >= 0 {
		depth := 0
		inStr := false
		esc := false
		for i := start; i < len(s); i++ {
			c := s[i]
			if esc {
				esc = false
				continue
			}
			if c == '\\' {
				esc = true
				continue
			}
			if c == '"' {
				inStr = !inStr
				continue
			}
			if inStr {
				continue
			}
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if depth == 0 {
					candidate := s[start : i+1]
					if strings.Contains(candidate, `"choices"`) {
						return []byte(candidate)
					}
					next := strings.Index(s[i+1:], "{")
					if next < 0 {
						return nil
					}
					start = i + 1 + next
					break
				}
			}
		}
		if depth != 0 {
			return nil
		}
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

func topFinding(r Report) string {
	if len(r.Findings) == 0 {
		return ""
	}
	for _, f := range r.Findings {
		if f.Category == "security" || f.Category == "overhaul" || f.Category == "exposure" {
			return f.Finding
		}
	}
	return r.Findings[0].Finding
}

func quoteTotal(q Quote) int {
	total := 0
	for _, item := range q.Items {
		total += item.Price
	}
	return total
}
