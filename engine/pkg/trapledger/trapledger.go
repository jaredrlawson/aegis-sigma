package trapledger

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Visit logs a single honeypot visitor — written by the Go trap server before
// it 302-redirects to GCP.
type Visit struct {
	TrapType string `json:"trap_type"`
	IP       string `json:"ip"`
	UA       string `json:"ua"`
	Referer  string `json:"referer"`
	Stage    string `json:"stage"` // e.g. "probe", "credential-submission"
	Ts       string `json:"ts"`
}

func RecordVisit(ip, ua, referer, trapType, stage string) {
	if ip == "" {
		return
	}
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	d.Exec(`INSERT INTO trap_visits (trap_id, ip, ua, referer, stage, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		trapID(trapType, ip, ua), ip, ua, referer, stage)
}

// RecordCredentials logs harvested credentials to trap_credentials.
// Called by the dashboard's GCP callback handler (see HandleStrikeCallback).
func RecordCredentials(ip, username, password, ua, trapType string) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	d.Exec(`INSERT INTO trap_credentials (ip, username, password, trap_type, user_agent, captured_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		ip, username, password, trapType, ua)
}

// PullFromGCP fetches captured credentials from the GCP strike server and
// persists them to trap_credentials. Called on a ticker by the dashboard.
func PullFromGCP() (int, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := config.StrikeURL + "/strike/status"
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("strike status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var stat struct {
		Active  map[string]interface{} `json:"active"`
		Log     []map[string]interface{} `json:"log"`
		Captures []map[string]interface{} `json:"captures"`
	}
	if json.Unmarshal(body, &stat) != nil {
		return 0, fmt.Errorf("bad json")
	}
	count := 0
	for _, c := range stat.Captures {
		ip, _ := c["ip"].(string)
		user, _ := c["username"].(string)
		pass, _ := c["password"].(string)
		ua, _ := c["ua"].(string)
		trapType, _ := c["trap_type"].(string)
		if ip == "" || (user == "" && pass == "") {
			continue
		}
		if !credentialExists(ip, user, pass) {
			RecordCredentials(ip, user, pass, ua, trapType)
			count++
		}
	}
	return count, nil
}

func credentialExists(ip, user, pass string) bool {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return false
	}
	defer d.Close()
	var n int
	d.QueryRow("SELECT COUNT(*) FROM trap_credentials WHERE ip = ? AND username = ? AND password = ?",
		ip, user, pass).Scan(&n)
	return n > 0
}

// All returns recent trap_visits + credential captures for the dashboard.
func All() (visits []map[string]interface{}, captures []map[string]interface{}) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}, []map[string]interface{}{}
	}
	defer d.Close()

	rows, err := d.Query(`SELECT id, trap_id, ip, ua, referer, stage, created_at
		FROM trap_visits ORDER BY id DESC LIMIT 100`)
	if err == nil {
		for rows.Next() {
			var id int
			var trapID, ip, ua, referer, stage, ts string
			rows.Scan(&id, &trapID, &ip, &ua, &referer, &stage, &ts)
			visits = append(visits, map[string]interface{}{
				"id": id, "trap_id": trapID, "ip": ip, "ua": ua,
				"referer": referer, "stage": stage, "created_at": ts,
			})
		}
		rows.Close()
	}
	if visits == nil {
		visits = []map[string]interface{}{}
	}

	crows, err := d.Query(`SELECT id, ip, username, password, trap_type, user_agent, captured_at
		FROM trap_credentials ORDER BY id DESC LIMIT 100`)
	if err == nil {
		for crows.Next() {
			var id int
			var ip, user, pass, trapType, ua, ts string
			crows.Scan(&id, &ip, &user, &pass, &trapType, &ua, &ts)
			captures = append(captures, map[string]interface{}{
				"id": id, "ip": ip, "username": user, "password": maskPass(pass),
				"trap_type": trapType, "user_agent": ua, "captured_at": ts,
			})
		}
		crows.Close()
	}
	if captures == nil {
		captures = []map[string]interface{}{}
	}
	return
}

func trapID(trapType, ip, ua string) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(trapType + "|" + ip + "|" + ua)))
	return "TRAP-" + fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func maskPass(p string) string {
	if len(p) <= 2 {
		return strings.Repeat("*", len(p))
	}
	return p[:1] + strings.Repeat("*", len(p)-2) + p[len(p)-1:]
}
