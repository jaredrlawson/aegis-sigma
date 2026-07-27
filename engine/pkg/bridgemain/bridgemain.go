package bridgemain

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const dbPath = "/mnt/data/databases/nomen.db"

type BridgeMain struct {
	db *sql.DB
}

func NewHandler() http.Handler {
	b := &BridgeMain{}
	b.db = b.openDB()
	if b.db != nil {
		initSchema(b.db)
	} else {
		log.Printf("[bridge-main] WARNING: could not open %s", dbPath)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", b.handleHealth)
	mux.HandleFunc("/api/stats", b.handleStats)
	mux.HandleFunc("/api/leads", b.handleLeads)
	mux.HandleFunc("/api/leads/add", b.handleLeadsAdd)
	mux.HandleFunc("/api/config", b.handleConfig)
	mux.HandleFunc("/api/targets", b.handleTargets)
	mux.HandleFunc("/api/tool", b.handleToolProxy)
	mux.HandleFunc("/api/monitor/", b.handleMonitor)
	mux.HandleFunc("/api/sales-team", b.handleSalesTeam)
	mux.HandleFunc("/api/sales-team/add", b.handleSalesTeamAdd)
	mux.HandleFunc("/api/sales/commissions", b.handleSalesCommissions)
	mux.HandleFunc("/api/leads/delete", b.handleLeadsDelete)
	mux.HandleFunc("/api/leads/update", b.handleLeadsUpdate)
	mux.HandleFunc("/api/leads/query", b.handleLeadsQuery)
	// Report and quote endpoints
	mux.HandleFunc("/api/leads/report", b.handleReport)
	mux.HandleFunc("/api/leads/quote", b.handleQuote)
	mux.HandleFunc("/api/leads/callprep", b.handleCallPrep)
	mux.HandleFunc("/api/leads/send-report", b.handleSendReport)
	mux.HandleFunc("/api/leads/send-quote", b.handleSendQuote)
	mux.HandleFunc("/api/stripe/webhook", b.handleStripeWebhook)
	mux.HandleFunc("/api/brevo/webhook", b.handleBrevoWebhook)
	// Booking endpoints
	mux.HandleFunc("/api/bookings", b.handleBookings)
	mux.HandleFunc("/api/bookings/create", b.handleBookingCreate)
	mux.HandleFunc("/api/bookings/cancel", b.handleBookingCancel)
	mux.HandleFunc("/api/bookings/slots", b.handleBookingSlots)
	return mux
}

func (b *BridgeMain) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{"status": "ok", "service": "bridge-main", "ts": time.Now().Unix()})
}

func (b *BridgeMain) handleStats(w http.ResponseWriter, r *http.Request) {
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	var total, sent, replied, unsubs int
	db.QueryRow("SELECT COUNT(*) FROM leads").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM leads WHERE outreach_sent=1").Scan(&sent)
	db.QueryRow("SELECT COUNT(*) FROM leads WHERE reply_received=1").Scan(&replied)
	db.QueryRow("SELECT COUNT(*) FROM leads WHERE status = 'unsubscribed'").Scan(&unsubs)
	jsonOut(w, map[string]interface{}{
		"total":        total,
		"sent":         sent,
		"replied":      replied,
		"unsubscribes": unsubs,
		"service":      "bridge-main",
	})
}

func (b *BridgeMain) handleLeads(w http.ResponseWriter, r *http.Request) {
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 5000 {
		limit = 5000
	}
	offset := (page - 1) * limit
	rows, err := db.Query(`SELECT id, domain, name, email, phone, address, city, state, zip, score, outreach_sent, reply_received, outreach_count, last_outreach, target_business, created_at, lat, lng
		FROM leads ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	defer rows.Close()
	var leads []map[string]interface{}
	for rows.Next() {
		var id, score, emailSent, replyReceived, outreachCount int
		var domain, name, email, created string
		var lastOutreach, phone, address, cityStr, state, zip, tbStr, latStr, lngStr sql.NullString
		err := rows.Scan(&id, &domain, &name, &email, &phone, &address, &cityStr, &state, &zip, &score, &emailSent, &replyReceived, &outreachCount, &lastOutreach, &tbStr, &created, &latStr, &lngStr)
		if err != nil {
			log.Printf("[bridge] scan error: %v", err)
			continue
		}
		latVal := 0.0
		lngVal := 0.0
		if latStr.Valid && latStr.String != "" {
			fmt.Sscanf(latStr.String, "%f", &latVal)
		}
		if lngStr.Valid && lngStr.String != "" {
			fmt.Sscanf(lngStr.String, "%f", &lngVal)
		}
		tb := ""
		if tbStr.Valid {
			tb = tbStr.String
		}
		leads = append(leads, map[string]interface{}{
			"id": id, "domain": domain, "name": name, "email": email,
			"phone": orEmpty(phone), "address": orEmpty(address), "city": orEmpty(cityStr), "state": orEmpty(state), "zip": orEmpty(zip),
			"score": score, "outreach_sent": emailSent, "reply_received": replyReceived,
			"outreach_count": outreachCount, "last_outreach": orEmpty(lastOutreach),
			"business_type": tb, "created_at": created,
			"lat": latVal, "lng": lngVal,
		})
	}
	if leads == nil {
		leads = []map[string]interface{}{}
	}
	var total int
	db.QueryRow("SELECT COUNT(*) FROM leads").Scan(&total)
	jsonOut(w, map[string]interface{}{"leads": leads, "page": page, "limit": limit, "total": total})
}

func (b *BridgeMain) handleLeadsAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}
	var lead map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&lead); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	get := func(key string) string {
		v, _ := lead[key].(string)
		return v
	}
	domain := get("domain")
	name := get("name")
	email := get("email")
	phone := get("phone")
	city := get("city")
	bizType := get("business_type")
	score, _ := strconv.Atoi(get("score"))
	if score == 0 {
		score = 50
	}

	_, err := db.Exec(`INSERT OR IGNORE INTO leads (domain, name, email, phone, score, city, target_business, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, name, email, phone, score, city, bizType, time.Now().Format(time.RFC3339))
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	jsonOut(w, map[string]interface{}{"ok": true, "domain": domain})
}

func (b *BridgeMain) handleConfig(w http.ResponseWriter, r *http.Request) {
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	if r.Method == http.MethodGet {
		cfg := map[string]string{}
		rows, err := db.Query("SELECT key, value FROM conf ORDER BY key")
		if err == nil {
			for rows.Next() {
				var k, v string
				rows.Scan(&k, &v)
				cfg[k] = v
			}
			rows.Close()
		}
		rows2, err2 := db.Query("SELECT key, value FROM config ORDER BY key")
		if err2 == nil {
			for rows2.Next() {
				var k, v string
				rows2.Scan(&k, &v)
				if _, exists := cfg[k]; !exists {
					cfg[k] = v
				}
			}
			rows2.Close()
		}
		jsonOut(w, cfg)
		return
	}
	if r.Method == http.MethodPost {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
			return
		}
		// Handle both formats: {"key":"k","value":"v"} and {"k":"v"}
		if key, ok := req["key"]; ok {
			if val, ok2 := req["value"]; ok2 {
				req = map[string]string{key: val}
			}
		}
		tx, err := db.Begin()
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
			return
		}
		stmt, err := tx.Prepare("INSERT INTO conf (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=?")
		if err != nil {
			tx.Rollback()
			jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
			return
		}
		defer stmt.Close()
		for k, v := range req {
			if _, err := stmt.Exec(k, v, v); err != nil {
				tx.Rollback()
				jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
				return
			}
		}
		if err := tx.Commit(); err != nil {
			jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
			return
		}
		jsonOut(w, map[string]interface{}{"ok": true})
		return
	}
	jsonOut(w, map[string]interface{}{"error": "method not allowed"}, 405)
}

func (b *BridgeMain) handleTargets(w http.ResponseWriter, r *http.Request) {
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	rows, err := db.Query("SELECT DISTINCT city FROM leads WHERE city IS NOT NULL AND city != '' ORDER BY city")
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	defer rows.Close()
	var cities []string
	for rows.Next() {
		var c string
		rows.Scan(&c)
		cities = append(cities, c)
	}
	if cities == nil {
		cities = []string{}
	}
	jsonOut(w, map[string]interface{}{"targets": cities})
}

func (b *BridgeMain) handleToolProxy(w http.ResponseWriter, r *http.Request) {
	proxyTo(w, r, "http://127.0.0.1:8901")
}

func (b *BridgeMain) handleMonitor(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{"status": "ok", "service": "bridge-main"})
}

func proxyTo(w http.ResponseWriter, r *http.Request, base string) {
	target := base + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	body, _ := io.ReadAll(r.Body)
	req, err := http.NewRequest(r.Method, target, strings.NewReader(string(body)))
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 502)
		return
	}
	for k, vals := range r.Header {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 502)
		return
	}
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// openDB returns the persistent database connection, or nil if unavailable.
func (b *BridgeMain) openDB() *sql.DB {
	if b.db != nil {
		return b.db
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil
	}
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	b.db = db
	initSchema(db)
	return db
}

func initSchema(db *sql.DB) {
	if db == nil {
		return
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS leads (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE,
		name TEXT,
		email TEXT,
		phone TEXT,
		score INTEGER DEFAULT 50,
		email_sent INTEGER DEFAULT 0,
		reply_received INTEGER DEFAULT 0,
		city TEXT,
		business_type TEXT,
		created_at TEXT
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS swot_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, created_at TEXT)`)
}

func orEmpty(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
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

func (b *BridgeMain) handleSalesTeam(w http.ResponseWriter, r *http.Request) {
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS sales_team (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT, email TEXT, phone TEXT,
		radius_miles INTEGER DEFAULT 50,
		leads_per_day INTEGER DEFAULT 5,
		leads_per_week INTEGER DEFAULT 25,
		cooldown_hours INTEGER DEFAULT 2,
		commission_pct INTEGER DEFAULT 10,
		quota_bonus_pct INTEGER DEFAULT 15,
		active INTEGER DEFAULT 1
	)`)
	rows, err := db.Query("SELECT id, name, email, phone, radius_miles, leads_per_day, leads_per_week, cooldown_hours, commission_pct, quota_bonus_pct, active FROM sales_team")
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	defer rows.Close()
	var list []map[string]interface{}
	for rows.Next() {
		var id, radius, lpd, lpw, cool, comm, qbonus, active int
		var name, email, phone string
		rows.Scan(&id, &name, &email, &phone, &radius, &lpd, &lpw, &cool, &comm, &qbonus, &active)
		list = append(list, map[string]interface{}{
			"id": id, "name": name, "email": email, "phone": phone,
			"radius_miles": radius, "leads_per_day": lpd, "leads_per_week": lpw,
			"cooldown_hours": cool, "commission_pct": comm, "quota_bonus_pct": qbonus,
			"active": active == 1,
		})
	}
	if list == nil {
		list = []map[string]interface{}{}
	}
	jsonOut(w, map[string]interface{}{"sales_team": list})
}

func (b *BridgeMain) handleSalesTeamAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS sales_team (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT, email TEXT, phone TEXT,
		radius_miles INTEGER DEFAULT 50,
		leads_per_day INTEGER DEFAULT 5,
		leads_per_week INTEGER DEFAULT 25,
		cooldown_hours INTEGER DEFAULT 2,
		commission_pct INTEGER DEFAULT 10,
		quota_bonus_pct INTEGER DEFAULT 15,
		active INTEGER DEFAULT 1
	)`)
	getStr := func(k, def string) string {
		v, _ := body[k].(string)
		if v == "" {
			return def
		}
		return v
	}
	getInt := func(k string, def int) int {
		if v, ok := body[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
		return def
	}
	_, err := db.Exec(`INSERT INTO sales_team (name, email, phone, radius_miles, leads_per_day, leads_per_week, cooldown_hours, commission_pct) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		getStr("name", ""), getStr("email", ""), getStr("phone", ""),
		getInt("radius_miles", 50), getInt("leads_per_day", 5), getInt("leads_per_week", 25),
		getInt("cooldown_hours", 2), getInt("commission_pct", 10))
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	jsonOut(w, map[string]interface{}{"ok": true})
}

func (b *BridgeMain) handleSalesCommissions(w http.ResponseWriter, r *http.Request) {
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS sales_commissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		salesman_name TEXT, domain TEXT, product_tier TEXT,
		sale_amount REAL, commission_pct INTEGER, commission_amount REAL,
		status TEXT DEFAULT 'pending', closed_at TEXT
	)`)
	rows, err := db.Query("SELECT id, salesman_name, domain, product_tier, sale_amount, commission_pct, commission_amount, status, closed_at FROM sales_commissions ORDER BY id DESC")
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	defer rows.Close()
	var list []map[string]interface{}
	for rows.Next() {
		var id, cpct int
		var smName, domain, tier, status, closed string
		var saleAmt, commAmt float64
		rows.Scan(&id, &smName, &domain, &tier, &saleAmt, &cpct, &commAmt, &status, &closed)
		list = append(list, map[string]interface{}{
			"id": id, "salesman_name": smName, "domain": domain,
			"product_tier": tier, "sale_amount": saleAmt, "commission_pct": cpct,
			"commission_amount": commAmt, "status": status, "closed_at": closed,
		})
	}
	if list == nil {
		list = []map[string]interface{}{}
	}
	jsonOut(w, map[string]interface{}{"commissions": list})
}

func (b *BridgeMain) handleLeadsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		jsonOut(w, map[string]interface{}{"error": "POST or DELETE only"}, 405)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	id, ok := body["id"]
	if !ok {
		jsonOut(w, map[string]interface{}{"error": "id required"}, 400)
		return
	}
	_, err := db.Exec("DELETE FROM email_opens WHERE lead_id = ?", id)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	_, err = db.Exec("DELETE FROM outreach WHERE lead_id = ?", id)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	_, err = db.Exec("DELETE FROM leads WHERE id = ?", id)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	jsonOut(w, map[string]interface{}{"ok": true})
}

func (b *BridgeMain) handleLeadsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	id, ok := body["id"]
	if !ok {
		jsonOut(w, map[string]interface{}{"error": "id required"}, 400)
		return
	}
	allowed := map[string]bool{"domain": true, "name": true, "email": true, "phone": true,
		"address": true, "city": true, "state": true, "zip": true, "score": true,
		"status": true, "notes": true, "outreach_sent": true, "reply_received": true,
		"outreach_count": true, "last_outreach": true, "target_business": true}
	for k, v := range body {
		if k == "id" {
			continue
		}
		if !allowed[k] {
			continue
		}
		_, err := db.Exec(fmt.Sprintf("UPDATE leads SET %s = ?, updated_at = datetime('now') WHERE id = ?", k), v, id)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
			return
		}
	}
	jsonOut(w, map[string]interface{}{"ok": true})
}

func (b *BridgeMain) handleLeadsQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	query := "SELECT id, domain, name, email, phone, score, outreach_sent, reply_received FROM leads WHERE 1=1"
	var args []interface{}
	if domain, ok := body["domain"].(string); ok && domain != "" {
		query += " AND domain = ?"
		args = append(args, domain)
	}
	if status, ok := body["status"].(string); ok && status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	if limit, ok := body["limit"].(float64); ok && limit > 0 {
		query += " LIMIT ?"
		args = append(args, int(limit))
	} else {
		query += " LIMIT 50"
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	defer rows.Close()
	var leads []map[string]interface{}
	for rows.Next() {
		var id, score, emailSent, replyReceived int
		var domain, name, email, phone string
		rows.Scan(&id, &domain, &name, &email, &phone, &score, &emailSent, &replyReceived)
		leads = append(leads, map[string]interface{}{
			"id": id, "domain": domain, "name": name, "email": email, "phone": phone,
			"score": score, "outreach_sent": emailSent, "reply_received": replyReceived,
		})
	}
	if leads == nil {
		leads = []map[string]interface{}{}
	}
	jsonOut(w, map[string]interface{}{"leads": leads})
}

// handleReport returns a structured report for a lead.
func (b *BridgeMain) handleReport(w http.ResponseWriter, r *http.Request) {
	leadID := r.URL.Query().Get("lead_id")
	domain := r.URL.Query().Get("domain")
	if leadID == "" && domain == "" {
		jsonOut(w, map[string]interface{}{"error": "lead_id or domain required"}, 400)
		return
	}

	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	var id, score int
	var d, name, email, city, state, bizType, notes string
	var phone, address sql.NullString
	if leadID != "" {
		err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''), score, COALESCE(target_business,''), COALESCE(notes,'')
			FROM leads WHERE id = ?`, leadID).Scan(&id, &d, &name, &email, &phone, &address, &city, &state, &score, &bizType, &notes)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
			return
		}
	} else {
		err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''), score, COALESCE(target_business,''), COALESCE(notes,'')
			FROM leads WHERE domain = ? LIMIT 1`, domain).Scan(&id, &d, &name, &email, &phone, &address, &city, &state, &score, &bizType, &notes)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
			return
		}
	}

	report := BuildReport(d, name, city, state, bizType, score, notes)
	jsonOut(w, map[string]interface{}{
		"domain":        report.Domain,
		"business_name": report.BusinessName,
		"city":          report.City,
		"state":         report.State,
		"business_type": report.BusinessType,
		"score":         report.Score,
		"risk_level":    report.RiskLevel,
		"findings":      report.Findings,
		"security_count": report.SecurityCount,
		"overhaul_count": report.OverhaulCount,
		"modern_count":  report.ModernCount,
		"summary":       report.Summary(),
	})
}

// handleQuote returns a quote with pricing for a lead.
func (b *BridgeMain) handleQuote(w http.ResponseWriter, r *http.Request) {
	leadID := r.URL.Query().Get("lead_id")
	domain := r.URL.Query().Get("domain")
	if leadID == "" && domain == "" {
		jsonOut(w, map[string]interface{}{"error": "lead_id or domain required"}, 400)
		return
	}

	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	var id, score int
	var d, name, email, city, state, bizType, notes string
	var phone, address sql.NullString
	if leadID != "" {
		err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''), score, COALESCE(target_business,''), COALESCE(notes,'')
			FROM leads WHERE id = ?`, leadID).Scan(&id, &d, &name, &email, &phone, &address, &city, &state, &score, &bizType, &notes)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
			return
		}
	} else {
		err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''), score, COALESCE(target_business,''), COALESCE(notes,'')
			FROM leads WHERE domain = ? LIMIT 1`, domain).Scan(&id, &d, &name, &email, &phone, &address, &city, &state, &score, &bizType, &notes)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
			return
		}
	}

	report := BuildReport(d, name, city, state, bizType, score, notes)
	quote := GeneratePricing(report, email)
	services := GetServices()
	matched := MatchServicesToFindings(report.Findings, services)

	jsonOut(w, map[string]interface{}{
		"domain":        quote.Domain,
		"business_name": quote.BusinessName,
		"email":         quote.Email,
		"items":         quote.Items,
		"total":         quote.Total,
		"summary":       quote.Summary,
		"services":      matched,
	})
}

// handleSendReport sends a clean report email to the prospect.
func (b *BridgeMain) handleSendReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}

	leadID, _ := body["lead_id"].(string)
	domain, _ := body["domain"].(string)
	email, _ := body["email"].(string)

	if leadID == "" && domain == "" {
		jsonOut(w, map[string]interface{}{"error": "lead_id or domain required"}, 400)
		return
	}

	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	var id, score int
	var d, name, city, state, bizType, notes string
	var e, phone, address sql.NullString
	if leadID != "" {
		err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''), score, COALESCE(target_business,''), COALESCE(notes,'')
			FROM leads WHERE id = ?`, leadID).Scan(&id, &d, &name, &e, &phone, &address, &city, &state, &score, &bizType, &notes)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
			return
		}
	} else {
		err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''), score, COALESCE(target_business,''), COALESCE(notes,'')
			FROM leads WHERE domain = ? LIMIT 1`, domain).Scan(&id, &d, &name, &e, &phone, &address, &city, &state, &score, &bizType, &notes)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
			return
		}
	}

	if email == "" && e.Valid {
		email = e.String
	}

	report := BuildReport(d, name, city, state, bizType, score, notes)
	report.Email = email

	sender := NewEmailSender()
	if err := sender.SendReport(report); err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}

	jsonOut(w, map[string]interface{}{"ok": true, "message": "Report sent to " + email})
}

// handleSendQuote sends a quote email with Stripe checkout link.
func (b *BridgeMain) handleSendQuote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}

	leadID, _ := body["lead_id"].(string)
	domain, _ := body["domain"].(string)
	email, _ := body["email"].(string)

	if leadID == "" && domain == "" {
		jsonOut(w, map[string]interface{}{"error": "lead_id or domain required"}, 400)
		return
	}

	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	var id, score int
	var d, name, city, state, bizType, notes string
	var e, phone, address sql.NullString
	if leadID != "" {
		err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''), score, COALESCE(target_business,''), COALESCE(notes,'')
			FROM leads WHERE id = ?`, leadID).Scan(&id, &d, &name, &e, &phone, &address, &city, &state, &score, &bizType, &notes)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
			return
		}
	} else {
		err := db.QueryRow(`SELECT id, COALESCE(domain,''), COALESCE(name,''), COALESCE(email,''), COALESCE(phone,''), COALESCE(address,''), COALESCE(city,''), COALESCE(state,''), score, COALESCE(target_business,''), COALESCE(notes,'')
			FROM leads WHERE domain = ? LIMIT 1`, domain).Scan(&id, &d, &name, &e, &phone, &address, &city, &state, &score, &bizType, &notes)
		if err != nil {
			jsonOut(w, map[string]interface{}{"error": "lead not found"}, 404)
			return
		}
	}

	if email == "" && e.Valid {
		email = e.String
	}

	report := BuildReport(d, name, city, state, bizType, score, notes)
	quote := GeneratePricing(report, email)

	// Create Stripe checkout session
	stripeClient := NewStripeClient()
	var checkoutURL string
	if stripeClient.Available() {
		session, err := stripeClient.CreateCheckoutSession(quote)
		if err != nil {
			log.Printf("[bridge] stripe session failed: %v", err)
		} else {
			checkoutURL = session.URL
		}
	}

	// Send email
	sender := NewEmailSender()
	if err := sender.SendQuote(quote, checkoutURL); err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}

	// Save quote to database
	if db != nil {
		itemsJSON, _ := json.Marshal(quote.Items)
		db.Exec(`CREATE TABLE IF NOT EXISTS quotes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			lead_id INTEGER, domain TEXT, email TEXT,
			items TEXT, total INTEGER, stripe_session_id TEXT,
			status TEXT DEFAULT 'sent', sent_at TEXT, created_at TEXT DEFAULT (datetime('now'))
		)`)
		db.Exec(`INSERT INTO quotes (lead_id, domain, email, items, total, stripe_session_id, status, sent_at)
			VALUES (?, ?, ?, ?, ?, ?, 'sent', datetime('now'))`,
			id, quote.Domain, quote.Email, string(itemsJSON), quote.Total, "")
	}

	jsonOut(w, map[string]interface{}{
		"ok":            true,
		"message":       "Quote sent to " + email,
		"checkout_url":  checkoutURL,
		"total":         quote.Total,
	})
}

// handleStripeWebhook processes Stripe payment notifications.
func (b *BridgeMain) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": "read body failed"}, 400)
		return
	}

	stripeClient := NewStripeClient()
	event, err := stripeClient.VerifyWebhookSignature(payload, r.Header.Get("Stripe-Signature"))
	if err != nil {
		log.Printf("[bridge] webhook verification failed: %v", err)
		jsonOut(w, map[string]interface{}{"error": "verification failed"}, 400)
		return
	}

	eventType, _ := event["type"].(string)
	if eventType == "checkout.session.completed" {
		session, _ := event["data"].(map[string]interface{})["object"].(map[string]interface{})
		sessionID, _ := session["id"].(string)
		metadata, _ := session["metadata"].(map[string]interface{})
		domain, _ := metadata["domain"].(string)

		log.Printf("[bridge] Stripe payment completed for %s (session: %s)", domain, sessionID)

		// Update quote status
		db := b.openDB()
		if db != nil {
			db.Exec(`UPDATE quotes SET status = 'paid', paid_at = datetime('now') WHERE stripe_session_id = ?`, sessionID)
			db.Exec(`UPDATE quotes SET status = 'paid', paid_at = datetime('now') WHERE domain = ? AND status = 'sent'`, domain)
		}
	}

	jsonOut(w, map[string]interface{}{"received": true})
}

// handleBrevoWebhook processes Brevo email bounce notifications.
func (b *BridgeMain) handleBrevoWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": "read body failed"}, 400)
		return
	}

	var event map[string]interface{}
	if err := json.Unmarshal(payload, &event); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}

	eventType, _ := event["event"].(string)
	email, _ := event["email"].(string)

	// Only process hard bounces and complaints
	if eventType != "hard_bounce" && eventType != "complaint" {
		jsonOut(w, map[string]interface{}{"received": true, "ignored": eventType})
		return
	}

	// Extract domain from email
	domain := ""
	if idx := strings.LastIndex(email, "@"); idx > 0 {
		domain = email[idx+1:]
	}

	if domain == "" {
		jsonOut(w, map[string]interface{}{"error": "no domain in email"}, 400)
		return
	}

	log.Printf("[bridge] Brevo bounce: %s (%s) — blocking domain %s", email, eventType, domain)

	// Add to blocked_domains table
	db := b.openDB()
	if db != nil {
	db.Exec(`CREATE TABLE IF NOT EXISTS blocked_domains (
		domain TEXT PRIMARY KEY,
		reason TEXT,
		email TEXT,
		blocked_at TEXT DEFAULT (datetime('now'))
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS bookings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		lead_id INTEGER,
		domain TEXT,
		slot_date TEXT,
		slot_time TEXT,
		status TEXT DEFAULT 'booked',
		notes TEXT,
		created_at TEXT DEFAULT (datetime('now'))
	)`)
}

	jsonOut(w, map[string]interface{}{"received": true, "blocked": domain})
}

// handleBookings lists all bookings (optionally filtered by date).
func (b *BridgeMain) handleBookings(w http.ResponseWriter, r *http.Request) {
	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}
	query := "SELECT id, lead_id, domain, slot_date, slot_time, status, notes, created_at FROM bookings"
	args := []interface{}{}
	if date := r.URL.Query().Get("date"); date != "" {
		query += " WHERE slot_date = ?"
		args = append(args, date)
	}
	query += " ORDER BY slot_date, slot_time"
	rows, err := db.Query(query, args...)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}
	defer rows.Close()
	var bookings []map[string]interface{}
	for rows.Next() {
		var id, leadID int
		var domain, slotDate, slotTime, status, notes, createdAt string
		rows.Scan(&id, &leadID, &domain, &slotDate, &slotTime, &status, &notes, &createdAt)
		bookings = append(bookings, map[string]interface{}{
			"id": id, "lead_id": leadID, "domain": domain,
			"date": slotDate, "time": slotTime, "status": status,
			"notes": notes, "created_at": createdAt,
		})
	}
	if bookings == nil {
		bookings = []map[string]interface{}{}
	}
	jsonOut(w, map[string]interface{}{"bookings": bookings})
}

// handleBookingCreate creates a new booking for a lead.
func (b *BridgeMain) handleBookingCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}
	leadID, _ := body["lead_id"].(float64)
	domain, _ := body["domain"].(string)
	slotDate, _ := body["date"].(string)
	slotTime, _ := body["time"].(string)
	notes, _ := body["notes"].(string)

	if slotDate == "" || slotTime == "" {
		jsonOut(w, map[string]interface{}{"error": "date and time required"}, 400)
		return
	}

	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	// Check for double-booking
	var existing int
	db.QueryRow("SELECT COUNT(*) FROM bookings WHERE slot_date = ? AND slot_time = ? AND status = 'booked'", slotDate, slotTime).Scan(&existing)
	if existing > 0 {
		jsonOut(w, map[string]interface{}{"error": "time slot already booked", "slot": slotDate + " " + slotTime}, 409)
		return
	}

	_, err := db.Exec("INSERT INTO bookings (lead_id, domain, slot_date, slot_time, status, notes) VALUES (?, ?, ?, ?, 'booked', ?)",
		int(leadID), domain, slotDate, slotTime, notes)
	if err != nil {
		jsonOut(w, map[string]interface{}{"error": err.Error()}, 500)
		return
	}

	// Update lead status
	if leadID > 0 {
		db.Exec("UPDATE leads SET status = 'booked' WHERE id = ?", int(leadID))
	}

	jsonOut(w, map[string]interface{}{"ok": true, "message": "Booked " + slotDate + " " + slotTime + " for " + domain})
}

// handleBookingCancel cancels a booking.
func (b *BridgeMain) handleBookingCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonOut(w, map[string]interface{}{"error": "POST only"}, 405)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonOut(w, map[string]interface{}{"error": "invalid JSON"}, 400)
		return
	}
	bookingID, _ := body["id"].(float64)
	if bookingID == 0 {
		jsonOut(w, map[string]interface{}{"error": "id required"}, 400)
		return
	}

	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	db.Exec("UPDATE bookings SET status = 'cancelled' WHERE id = ?", int(bookingID))
	jsonOut(w, map[string]interface{}{"ok": true})
}

// handleBookingSlots returns available time slots for a given date.
func (b *BridgeMain) handleBookingSlots(w http.ResponseWriter, r *http.Request) {
	date := r.URL.Query().Get("date")
	if date == "" {
		jsonOut(w, map[string]interface{}{"error": "date required"}, 400)
		return
	}

	db := b.openDB()
	if db == nil {
		jsonOut(w, map[string]interface{}{"error": "database unavailable"}, 500)
		return
	}

	// Get booked slots for this date
	booked := map[string]bool{}
	rows, _ := db.Query("SELECT slot_time FROM bookings WHERE slot_date = ? AND status = 'booked'", date)
	if rows != nil {
		for rows.Next() {
			var t string
			rows.Scan(&t)
			booked[t] = true
		}
		rows.Close()
	}

	// Generate available slots (9 AM - 5 PM, hourly)
	slots := []map[string]interface{}{}
	for hour := 9; hour <= 17; hour++ {
		timeStr := fmt.Sprintf("%d:00", hour)
		if hour > 12 {
			timeStr = fmt.Sprintf("%d:00", hour)
		}
		isAvailable := !booked[timeStr]
		slots = append(slots, map[string]interface{}{
			"time":      timeStr,
			"available": isAvailable,
		})
	}

	jsonOut(w, map[string]interface{}{"date": date, "slots": slots})
}
