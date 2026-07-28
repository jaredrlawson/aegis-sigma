package triadclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

var (
	cache     = map[string]cacheEntry{}
	cacheTTL  = config.CacheTTL
	rateCalls []time.Time
)

type cacheEntry struct {
	result map[string]interface{}
	ts     time.Time
}

func getAPIKey() string {
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return key
	}
	data, err := os.ReadFile(config.VaultKeyPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func checkRateLimit() bool {
	now := time.Now()
	cutoff := now.Add(-60 * time.Second)
	filtered := []time.Time{}
	for _, t := range rateCalls {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	rateCalls = filtered
	if len(rateCalls) >= config.RateLimitPerMin {
		return false
	}
	rateCalls = append(rateCalls, now)
	return true
}

func callLLM(model string, messages []map[string]string, maxTokens int) string {
	apiKey := getAPIKey()
	if apiKey == "" || !checkRateLimit() {
		return ""
	}

	body := map[string]interface{}{
		"model":      model,
		"messages":   messages,
		"max_tokens": maxTokens,
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", config.LoadConfig().LLM.BaseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Choices) > 0 {
		return result.Choices[0].Message.Content
	}
	return ""
}

func extractJSON(text string) map[string]interface{} {
	start := strings.Index(text, "{")
	if start == -1 {
		return nil
	}
	depth := 0
	for i := start; i < len(text); i++ {
		if text[i] == '{' {
			depth++
		} else if text[i] == '}' {
			depth--
			if depth == 0 {
				var result map[string]interface{}
				if json.Unmarshal([]byte(text[start:i+1]), &result) == nil {
					return result
				}
				return nil
			}
		}
	}
	return nil
}

func sanitizeInput(text string) string {
	patterns := []string{`(?i)ignore\s+previous\s+instructions`, `(?i)you\s+are\s+now`, `(?i)\[SYSTEM\]`}
	result := text
	for _, pat := range patterns {
		re := regexp.MustCompile(pat)
		result = re.ReplaceAllString(result, "[REDACTED]")
	}
	if len(result) > 2000 {
		result = result[:2000]
	}
	return result
}

func ShieldCheck(params map[string]interface{}) map[string]interface{} {
	score, reasons := ruleBasedCheck(params)
	if score >= 50 {
		return map[string]interface{}{
			"verdict": "block", "confidence": float64(score) / 100.0,
			"reason": strings.Join(reasons, "; "), "threat_level": "high",
		}
	}
	if score <= 20 {
		return map[string]interface{}{
			"verdict": "pass", "confidence": 1.0 - float64(score)/100.0,
			"reason": "rules_clean", "threat_level": "low",
		}
	}
	apiKey := getAPIKey()
	if apiKey == "" {
		return map[string]interface{}{
			"verdict": "pass", "confidence": 0.5, "reason": "no_llm", "threat_level": "low",
		}
	}
	messages := []map[string]string{
		{"role": "system", "content": "You are AEGIS-SIGMA Shield. Analyze requests for threats. Return JSON: {\"verdict\": \"block\"|\"pass\", \"confidence\": 0.0-1.0, \"reason\": \"string\", \"threat_level\": \"low\"|\"medium\"|\"high\"|\"critical\"}"},
		{"role": "user", "content": fmt.Sprintf("%v", params)},
	}
	response := callLLM(config.LoadConfig().LLM.ModelShield, messages, 256)
	result := extractJSON(response)
	if result == nil {
		return map[string]interface{}{"verdict": "pass", "confidence": 0.5, "reason": "llm_parse_failed"}
	}
	return result
}

func SoulEngine(prompt string) map[string]interface{} {
	apiKey := getAPIKey()
	if apiKey == "" {
		return map[string]interface{}{"assessment": "no_llm", "confidence": 0.0}
	}
	messages := []map[string]string{
		{"role": "system", "content": "You are AEGIS-SIGMA Soul. Analyze attacks. Return JSON with assessment, attacker_type, confidence, indicators, recommendation."},
		{"role": "user", "content": sanitizeInput(prompt)},
	}
	response := callLLM(config.LoadConfig().LLM.ModelSoul, messages, 1024)
	result := extractJSON(response)
	if result == nil {
		return map[string]interface{}{"assessment": "llm_parse_failed", "confidence": 0.0}
	}
	return result
}

func ruleBasedCheck(params map[string]interface{}) (int, []string) {
	score := 0
	var reasons []string
	ua, _ := params["ua"].(string)
	path, _ := params["path"].(string)
	uaL := strings.ToLower(ua)
	pathL := strings.ToLower(path)

	attackTools := []string{"sqlmap", "nmap", "nikto", "gobuster", "masscan", "zgrab", "wpscan", "acunetix"}
	for _, tool := range attackTools {
		if strings.Contains(uaL, tool) {
			score += 80
			reasons = append(reasons, "attack_tool:"+tool)
		}
	}
	suspicious := []string{".env", ".git", "wp-admin", "wp-login", "xmlrpc", "phpinfo", "actuator", "heapdump"}
	for _, pat := range suspicious {
		if strings.Contains(pathL, pat) {
			score += 70
			reasons = append(reasons, "suspicious_path:"+pat)
		}
	}
	if ua == "" || len(ua) < 10 {
		score += 30
		reasons = append(reasons, "missing_ua")
	}
	scriptClients := []string{"curl", "wget", "python-requests", "go-http", "java/", "perl"}
	for _, sc := range scriptClients {
		if strings.Contains(uaL, sc) {
			score += 40
			reasons = append(reasons, "script_client:"+sc)
		}
	}
	if score > 100 {
		score = 100
	}
	return score, reasons
}
