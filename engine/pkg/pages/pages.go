package pages

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

//go:embed block.html
var blockHTML string

//go:embed challenge.html
var challengeHTML string

//go:embed terminal_void.html
var terminalVoidHTML string

//go:embed not_found.html
var notFoundHTML string

//go:embed forbidden.html
var forbiddenHTML string

func BlockPage(ip, reason, actor, severity, caseID string, consensus float64) string {
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	color := "#ff6d00"
	if severity == "critical" {
		color = "#ff1744"
	}
	return fmt.Sprintf(blockHTML,
		ts, caseID, ip, actor, reason,
		fmt.Sprintf("%.4f", consensus), color, severity)
}

func ChallengePage(ip, ua, redirect, strikeURL string) string {
	puzzle := GeneratePuzzle(1)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	if strikeURL == "" {
		strikeURL = config.LoadConfig().Strike.URL
	}
	r := strings.NewReplacer(
		"{{IP}}", ip,
		"{{UA}}", ua,
		"{{TS}}", ts,
		"{{PUZZLE}}", puzzle,
		"{{REDIRECT}}", redirect,
		"{{STRIKE_URL}}", strikeURL,
	)
	return r.Replace(challengeHTML)
}

func TerminalVoidPage(ip, reason, caseID string) string {
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	return fmt.Sprintf(terminalVoidHTML, caseID, ip, reason, ts)
}

func NotFoundPage(ip, path string) string {
	return fmt.Sprintf(notFoundHTML, path)
}

func ForbiddenPage(ip, reason string) string {
	return fmt.Sprintf(forbiddenHTML, reason)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── PUZZLES ────────────────────────────────────────────────────────

var fib = []int{1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765}

type Puzzle struct {
	Type     string
	Sequence string
	Answer   int
}

func GeneratePuzzle(difficulty int) string {
	if rand.Intn(2) == 0 {
		return generateFibonacci(difficulty)
	}
	return generateTesla(difficulty)
}

func generateFibonacci(difficulty int) string {
	start := 0
	if difficulty-1 > 0 {
		start = difficulty - 1
	}
	if start+6 > len(fib) {
		start = 0
	}
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = fmt.Sprintf("%d", fib[start+i])
	}
	return strings.Join(parts, " &rarr; ") + " &rarr; <strong>?</strong>"
}

func generateTesla(difficulty int) string {
	base := difficulty * 3
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = fmt.Sprintf("%d", base+i*3)
	}
	missingIdx := rand.Intn(6)
	parts[missingIdx] = "_"
	return strings.Join(parts, ", ")
}

// ── CHALLENGE COOKIE ───────────────────────────────────────────────

func GenerateChallengeCookie(ip, ua string) string {
	ts := time.Now().UnixMilli()
	payload := fmt.Sprintf("%d|%s", ts, ua)
	return base64Encode(payload)
}

func GenerateSlidingCookie(ip, ua string) string {
	return sha256Hex(ip + ":" + normalizeUA(ua) + ":sliding")
}

func ValidateChallengeCookie(cookieVal, reqUA, reqIP string) bool {
	if cookieVal == "" {
		return false
	}
	// Sliding hash (32 char hex) — keyed on full UA + normalized IP.
	// Both gen and validate MUST use the same UA (no truncation); the only
	// allowed slack is empty UA (server-side scrape with no UA at all).
	if len(cookieVal) == 32 {
		expected := sha256Hex(reqIP + ":" + normalizeUA(reqUA) + ":sliding")
		return cookieVal == expected
	}
	// Base64 encoded — legacy path, retains UA comparison but allows the
	// empty-UA corner case.
	decoded, err := base64Decode(cookieVal)
	if err != nil {
		return false
	}
	parts := strings.SplitN(decoded, "|", 2)
	if len(parts) < 2 {
		return false
	}
	var ts int64
	fmt.Sscanf(parts[0], "%d", &ts)
	age := time.Now().UnixMilli() - ts
	if age < 0 || age > 3600000 {
		return false
	}
	cookieUA := parts[1]
	if cookieUA != "" && reqUA != "" && cookieUA != reqUA {
		return false
	}
	return true
}

// normalizeUA trims whitespace and lowercases the User-Agent string so
// cookie generation and validation always use the same form, even if
// nginx or the browser slightly reformats the header between requests.
func normalizeUA(ua string) string {
	return strings.ToLower(strings.TrimSpace(ua))
}

func sha256Hex(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
