package blockledger

import (
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Block is the durable ledger entry for a banned IP. The Shield consults this
// table on every request before deciding to classify. Voidpunisher continues
// to deploy iptables for tier-4, but the durable source of truth is here.

// BlockIP records an IP as blocked with reason + tenant info.
// If a record already exists, strikes are incremented and reason updated.
func BlockIP(ip, reason, tenant string, strikes int) {
	if ip == "" {
		return
	}
	if tenant == "" {
		tenant = "global"
	}
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	var existing int
	d.QueryRow("SELECT COUNT(*) FROM blocked_ips WHERE ip = ?", ip).Scan(&existing)
	if existing == 0 {
		d.Exec(`INSERT INTO blocked_ips (ip, strikes, banned, reason, source_tenant, blocked_at)
			VALUES (?, ?, 1, ?, ?, ?)`,
			ip, strikes, reason, tenant, time.Now().UTC().Format("2006-01-02 15:04:05"))
		return
	}
	_, _ = d.Exec(`UPDATE blocked_ips SET
		strikes = strikes + ?, reason = ?,
		banned = 1, blocked_at = ?
		WHERE ip = ?`,
		strikes, reason, time.Now().UTC().Format("2006-01-02 15:04:05"), ip)
}

// UnblockIP removes an IP from the durable ledger.
func UnblockIP(ip string) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	_, _ = d.Exec("DELETE FROM blocked_ips WHERE ip = ?", ip)
}

// IsBlocked returns true and the reason if the IP is currently banned.
func IsBlocked(ip string) (bool, string) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return false, ""
	}
	defer d.Close()
	var banned int
	var reason string
	err = d.QueryRow("SELECT COALESCE(banned,0), COALESCE(reason,'') FROM blocked_ips WHERE ip = ?", ip).Scan(&banned, &reason)
	if err != nil {
		return false, ""
	}
	return banned == 1, reason
}

// All returns blocked IPs for the dashboard.
func All() []map[string]interface{} {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT b.ip, b.strikes, b.banned, b.reason, b.source_tenant, b.blocked_at
		FROM blocked_ips b ORDER BY b.blocked_at DESC LIMIT 200`)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var ip, reason, tenant, ts string
		var strikes, banned int
		rows.Scan(&ip, &strikes, &banned, &reason, &tenant, &ts)
		out = append(out, map[string]interface{}{
			"ip":            ip,
			"strikes":       strikes,
			"banned":        banned == 1,
			"reason":        reason,
			"source_tenant": tenant,
			"blocked_at":    ts,
		})
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}

// Count returns the number of currently-banned IPs.
func Count() int {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0
	}
	defer d.Close()
	var n int
	d.QueryRow("SELECT COUNT(*) FROM blocked_ips WHERE banned = 1").Scan(&n)
	return n
}

// IsBlockedNow checks if an IP is already in the blocked table (fast, no logging).
func IsBlockedNow(ip string) bool {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return false
	}
	defer d.Close()
	var n int
	d.QueryRow("SELECT COUNT(*) FROM blocked_ips WHERE ip = ? AND banned = 1", ip).Scan(&n)
	return n > 0
}
