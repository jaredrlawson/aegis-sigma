package config

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"gopkg.in/yaml.v3"
)

const (
	HealthToken       = "" // Set via vault or config.yaml
	CEngineHost       = "127.0.0.1"
	CEnginePort       = 20129
	CEngineTimeout    = 10000 * time.Millisecond
	GeoIPURL          = "http://127.0.0.1:4040"
	BrainDB           = "/var/lib/aegis-shield-soul/brain.sqlite"
	EvidenceDir       = "/var/log/aegis"
	EvidenceFile      = "/var/log/aegis/fbi-evidence.jsonl"
	LiveFile          = "/var/log/aegis/live_events.jsonl"
	BlockLog          = "/var/log/aegis/aegis-shield.log"
	IptablesChain     = "AEGIS_VOID"
	VaultKeyPath      = "/etc/aegis-sigma/vault/openrouter.key"
	EnsembleThreshold = 0.618
	WeightAlpha       = 0.55
	WeightBeta        = 0.34
	WeightGamma       = 0.11
	RateLimitPerMin   = 30
	CacheTTL          = 300 * time.Second
	PHI               = 1.618033988749895
	ShieldPort        = 3000
	SoulPort          = 3007
	TrapPort          = 3001
	GeoIPPort         = 4040
	ConfigPath        = "/etc/aegis-sigma/config.yaml"
	VaultDir          = "/etc/aegis-sigma/vault"
)

// YamlConfig mirrors config.yaml structure.
type YamlConfig struct {
	Network struct {
		WireguardIP string `yaml:"wireguard_ip"`
	} `yaml:"network"`
	LLM struct {
		BaseURL     string `yaml:"base_url"`
		APIKey      string `yaml:"api_key"`
		ModelShield string `yaml:"model_shield"`
		ModelSoul   string `yaml:"model_soul"`
		ModelTeacher  string `yaml:"model_teacher"`
		ModelCallPrep string `yaml:"model_callprep"`
	} `yaml:"llm"`
	Strike struct {
		URL string `yaml:"url"`
	} `yaml:"strike"`
	Landing struct {
		URL string `yaml:"url"`
	} `yaml:"landing"`
	Tier     string `yaml:"tier"`
	Features struct {
		MaxAgents      int  `yaml:"max_agents"`
	} `yaml:"features"`
}

var (
	Cfg     YamlConfig
	cfgOnce sync.Once
)

// LoadConfig reads config.yaml once, falls back to defaults.
func LoadConfig() YamlConfig {
	cfgOnce.Do(func() {
		Cfg = defaultConfig()
		data, err := os.ReadFile(ConfigPath)
		if err == nil {
			_ = yaml.Unmarshal(data, &Cfg)
		}
		// Apply defaults for empty fields
		if Cfg.Network.WireguardIP == "" {
			Cfg.Network.WireguardIP = "127.0.0.1"
		}
		if Cfg.LLM.BaseURL == "" {
			Cfg.LLM.BaseURL = "https://ai.aegis-sigma.com/v1"
		}
		if Cfg.LLM.ModelShield == "" {
			Cfg.LLM.ModelShield = "google/gemini-2.5-flash"
		}
		if Cfg.LLM.ModelSoul == "" {
			Cfg.LLM.ModelSoul = "sambanova/gpt-oss-120b"
		}
		if Cfg.LLM.APIKey == "" {
			Cfg.LLM.APIKey = ReadVault("openrouter.key")
		}
		if Cfg.Strike.URL == "" {
			Cfg.Strike.URL = "http://localhost:8443"
		}
		if Cfg.Landing.URL == "" {
			Cfg.Landing.URL = "http://127.0.0.1:8081"
		}
		if Cfg.Tier == "" {
			Cfg.Tier = "community"
		}
		if Cfg.Features.MaxAgents == 0 {
			Cfg.Features.MaxAgents = 15
		}
	})
	return Cfg
}

func defaultConfig() YamlConfig {
	return YamlConfig{}
}

// ReadVault reads a secret from the vault directory.
func ReadVault(name string) string {
	data, err := os.ReadFile(VaultDir + "/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// IsFeatureEnabled checks if a feature is available for the current tier.
func IsFeatureEnabled(feature string) bool {
	return false
}

// StrikeURL is the counter-attack server. Read from config.yaml.
var StrikeURL = "http://localhost:8443"

// LandingURL is the origin backend. Read from config.yaml.
var LandingURL = "http://127.0.0.1:8081"

// SiteBackends is the fallback map for infra sites.
// DB-backed RouteCache (from brain.sqlite) takes precedence.
var SiteBackends = map[string]string{}

// RouteCache is the in-memory copy of shield_routes from brain.sqlite.
var RouteCache = map[string]string{}
var routeCacheMu sync.RWMutex

func StartRouteCache() {
	refreshRoutes()
	go func() {
		for range time.Tick(60 * time.Second) {
			refreshRoutes()
		}
	}()
}

func refreshRoutes() {
	d, err := sql.Open("sqlite", BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	rows, err := d.Query("SELECT domain, backend_url FROM shield_routes WHERE active = 1")
	if err != nil {
		return
	}
	defer rows.Close()
	newCache := map[string]string{}
	for rows.Next() {
		var domain, backend string
		if rows.Scan(&domain, &backend) == nil {
			newCache[domain] = backend
		}
	}
	routeCacheMu.Lock()
	RouteCache = newCache
	routeCacheMu.Unlock()
}

func BackendForHost(host string) string {
	routeCacheMu.RLock()
	if b, ok := RouteCache[host]; ok {
		routeCacheMu.RUnlock()
		return b
	}
	routeCacheMu.RUnlock()
	cfg := LoadConfig()
	if b, ok := SiteBackends[host]; ok {
		return b
	}
	return cfg.Landing.URL
}

var TrustedPrefixes = []string{
	"127.", "::1", "0.0.0.0",
	"10.88.", "10.89.", "::ffff:10.88.", "::ffff:10.89.",
}

var GoodBots = []string{
	"Googlebot", "Bingbot", "Slurp", "DuckDuckBot", "Baidu",
	"YandexBot", "Sogou", "Exabot", "facebookexternalhit",
	"Twitterbot", "LinkedInBot",
}

var Honeypaths = []string{
	".aws/credentials", ".env", ".git/config", "wp-admin", "wp-login",
	"xmlrpc.php", "phpmyadmin", "adminer.php", "actuator", "heapdump",
	"server-status", "debug.log", "docker-compose.yml", "config.yml",
	"console/", "phpinfo.php", ".git/HEAD", "wp-config.php.bak",
}

var FederalCodes = map[string]map[string]interface{}{
	"xmlrpc":   {"sar": "MF-20-EXEC-CMD", "fbi": "Hacking - WordPress XMLRPC Abuse", "mitre": []string{"T1190"}},
	"git":      {"sar": "MF-26-LA-OPEN-DIR", "fbi": "Data Breach Risk - Exposed Repository", "mitre": []string{"T1213"}},
	"wp-admin": {"sar": "MF-20-EXEC-CMD", "fbi": "Hacking - Unauthorized Admin Access", "mitre": []string{"T1078"}},
	"wp-login": {"sar": "MF-20-EXEC-CMD", "fbi": "Hacking - WordPress Login Brute", "mitre": []string{"T1110"}},
	"aws":      {"sar": "MF-26-LA-OPEN-DIR", "fbi": "Data Breach Risk - Cloud Credentials", "mitre": []string{"T1552"}},
	"env":      {"sar": "MF-26-LA-OPEN-DIR", "fbi": "Data Breach Risk - Environment File", "mitre": []string{"T1552"}},
	"phpinfo":  {"sar": "MF-26-LA-OPEN-DIR", "fbi": "Data Breach Risk - Info Disclosure", "mitre": []string{"T1592"}},
	"login":    {"sar": "MF-24-ZEE-SCAN", "fbi": "Unauthorized Access Attempt", "mitre": []string{"T1078"}},
	"default":  {"sar": "MF-24-ZEE-SCAN", "fbi": "Computer Crimes - Scanner Activity", "mitre": []string{"T1595"}},
}

var MonitoredServices = []string{
	"aegis-shield-go", "aegis-soul-go", "aegis-trap-go", "aegis-geoip-go",
	"aegis-c",
}

var MonitoredPorts = []int{3000, 3001, 3007, 20129, 8086, 4040}

// RequireTelemetry enforces telemetry for the free edition.
// The service refuses to start without it.
func RequireTelemetry() {
	data, err := os.ReadFile("/etc/aegis-sigma/.env")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "TELEMETRY=") && strings.HasSuffix(line, "=true") {
				return
			}
		}
	}
	// Also check environment variable
	if os.Getenv("TELEMETRY") == "true" {
		return
	}
	fmt.Fprintln(os.Stderr, "[AEGIS-SIGMA] TELEMETRY is required for the free edition.")
	fmt.Fprintln(os.Stderr, "[AEGIS-SIGMA] Set TELEMETRY=true in /etc/aegis-sigma/.env or upgrade to Pro.")
	os.Exit(1)
}
