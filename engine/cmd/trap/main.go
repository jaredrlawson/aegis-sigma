package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

// ── HONEYPOT FAKE CONTENT ──────────────────────────────────────────

var fakeLogins = map[string]string{
	"/cpanel":         `{"status":"ok","message":"cPanel Login","version":"11.118.0.9"}`,
	"/webmail":        `{"status":"ok","message":"Webmail Login","version":"Roundcube 1.6.7"}`,
	"/phpmyadmin":     `{"status":"ok","message":"phpMyAdmin 5.2.1","version":"5.2.1"}`,
	"/jenkins":        `{"status":"ok","message":"Jenkins Dashboard","version":"2.440.3"}`,
	"/gitlab":         `{"status":"ok","message":"GitLab CE 16.8","version":"16.8.0"}`,
	"/admin":          `{"status":"ok","message":"Admin Panel","version":"3.2.1"}`,
	"/login":          `{"status":"ok","message":"Login Portal","version":"1.0"}`,
	"/wp-login.php":   `{"status":"ok","message":"WordPress Login","version":"6.4.3"}`,
	"/xmlrpc.php":     `{"status":"ok","message":"XML-RPC Server","version":"2.0"}`,
	"/actuator":       `{"status":"ok","message":"Spring Boot Actuator","version":"3.2.1"}`,
	"/server-status":  `{"status":"ok","message":"Apache Server Status","version":"2.4.58"}`,
	"/.env":           "DB_PASSWORD=fake_secret_123\nAWS_KEY=AKIA1234EXAMPLE\nDEBUG=true\n",
	"/.git/config":    "[core]\nrepositoryformatversion = 0\n[remote \"origin\"]\nurl = git@github.com:company/internal.git\n",
	"/.git/HEAD":      "ref: refs/heads/main\n",
	"/.aws/credentials": "[default]\naws_access_key_id = AKIA1234EXAMPLE\naws_secret_access_key = fake_secret\n",
	"/phpinfo.php":    `<?php phpinfo(); ?>`,
	"/debug.log":      "[2026-07-23] ERROR: Database connection failed\n[2026-07-23] WARN: Retry attempt 3\n",
	"/backup.sql":     "-- MySQL dump 10.13\n-- Host: localhost\n-- Database: wordpress\n",
	"/database.sql":   "CREATE TABLE users (id INT, name VARCHAR(255));\n",
	"/docker-compose.yml": "version: '3'\nservices:\n  db:\n    image: mysql:8\n    environment:\n      MYSQL_ROOT_PASSWORD: root123\n",
}

// ── TARPIT WEAPONS ─────────────────────────────────────────────────

func serveTarpit(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flusher", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	flusher.Flush()

	// Send 1 byte every 20 seconds for up to 10 minutes
	for i := 0; i < 30; i++ {
		w.Write([]byte("0"))
		flusher.Flush()
		time.Sleep(20 * time.Second)
	}
}

func serveSlowLoris(w http.ResponseWriter) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	flusher.Flush()

	// Send random bytes very slowly
	for i := 0; i < 60; i++ {
		b := make([]byte, 1)
		b[0] = byte(rand.Intn(256))
		w.Write(b)
		flusher.Flush()
		time.Sleep(5 * time.Second)
	}
}

func serveConnectionSaturation(w http.ResponseWriter) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(200)
	flusher.Flush()

	// Fibonacci-timed 16KB hex junk writes
	fib := []int{1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144}
	payload := bytes.Repeat([]byte("DEADBEEF"), 2048) // 16KB
	for _, delay := range fib {
		w.Write(payload)
		flusher.Flush()
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
}

// ── CPU FRY ─────────────────────────────────────────────────────────

func serveCPUFry(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write([]byte(`{"status":"processing","job_id":"`))
	
	// Generate massive JSON payload to fry client CPU
	junk := make([]byte, 0)
	for i := 0; i < 100000; i++ {
		junk = append(junk, []byte(fmt.Sprintf(`{"key%d":"val%d","nested":{"a":%d,"b":%d},"array":[`, i, i, i*2, i*3))...)
	}
	w.Write(junk)
}

// ── DISK FILL ──────────────────────────────────────────────────────

func serveGzipBomb(w http.ResponseWriter) {
	// Serve a 256KB compressed file that decompresses to ~1GB
	var buf bytes.Buffer
	w2, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	data := make([]byte, 65536)
	for i := range data {
		data[i] = byte(i % 256)
	}
	for i := 0; i < 16384; i++ {
		w2.Write(data)
	}
	w2.Close()

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.Header().Set("Content-Disposition", "attachment; filename=\"config.php.bak\"")
	w.WriteHeader(200)
	io.Copy(w, &buf)
}

// ── SQL INJECTION HONEYTRAP ────────────────────────────────────────

func serveSQLTrap(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"error":"SQL syntax; check the manual that corresponds to your MySQL server version","status":500,"query":"SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin--","hint":"Hint: Use LOAD_FILE('/etc/passwd') to read files"}`))
}

// ── HONEYPOT DB (capture attacker creds) ────────────────────────────

var capturedCreds = []map[string]interface{}{}

func captureCreds(ip, ua, path string, body map[string]interface{}) {
	entry := map[string]interface{}{
		"ts":     time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"ip":     ip,
		"ua":     ua,
		"path":   path,
		"creds":  body,
		"hash":   fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s", ip, ua))))[:16],
	}
	capturedCreds = append(capturedCreds, entry)

	f, err := os.OpenFile(config.EvidenceDir+"/honeypot-captures.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		data, _ := json.Marshal(entry)
		f.Write(data)
		f.WriteString("\n")
	}
}

// ── MAIN ────────────────────────────────────────────────────────────

func main() {
	os.MkdirAll(config.EvidenceDir, 0755)

	// All honeypot paths → trap content
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		ip := r.RemoteAddr
		ua := r.UserAgent()

		// Fake login pages
		if content, ok := fakeLogins[path]; ok {
			captureCreds(ip, ua, path, nil)
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(fmt.Sprintf("<html><head><title>%s</title></head><body><h1>%s</h1><form><input name='user' placeholder='Username'><input name='pass' type='password' placeholder='Password'><button>Login</button></form></body></html>", path, content)))
			return
		}

		// SQL injection trap
		if strings.Contains(path, "sql") || strings.Contains(path, "query") {
			serveSQLTrap(w)
			return
		}

		// Tarpit endpoints
		if strings.Contains(path, "tarpit") || strings.Contains(path, "slow") {
			serveTarpit(w, r)
			return
		}

		// CPU fry
		if strings.Contains(path, "fry") || strings.Contains(path, "cpu") {
			serveCPUFry(w)
			return
		}

		// Gzip bomb
		if strings.Contains(path, "bomb") || strings.Contains(path, "download") {
			serveGzipBomb(w)
			return
		}

		// Connection saturation
		if strings.Contains(path, "saturation") || strings.Contains(path, "flood") {
			serveConnectionSaturation(w)
			return
		}

		// Default: serve generic trap page
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","version":"1.0","service":"api"}`))
	})

	http.HandleFunc("/api/v1/trap/callback", func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		ua := r.UserAgent()
		captureCreds(ip, ua, "/api/v1/trap/callback", nil)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	fmt.Printf("[TRAP] Go honeypot on :%d\n", config.TrapPort)
	fmt.Printf("[TRAP] Weapons: tarpit, cpu-fry, disk-bomb, fake-logins, sql-trap, saturation\n")
	http.ListenAndServe(fmt.Sprintf(":%d", config.TrapPort), nil)
}
