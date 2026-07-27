package extractor

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

var (
	honeytokenPatterns = regexp.MustCompile(`(?i)\.aws[\\/]*(config|credentials)|\.env|config\.yml|config\.yaml|actuator[/\\]|server-status|phpmyadmin|wp-admin|wp-login|xmlrpc\.php|\.git[/\\]config|docker-compose\.yml|adminer\.php|debug\.log|console[/\\]|heapdump`)
	hostileUAPatterns  = regexp.MustCompile(`(?i)^nmap|Nmap Scripting Engine|nikto|sqlmap|masscan|^gobuster|^zgrab|^dirbuster|^wpscan|^arachni|w3af|havij|acunetix`)
	genericUAPatterns  = regexp.MustCompile(`(?i)curl|wget|python-requests|python-urllib|Go-http-client|java[/\\]|libwww|perl|scrapy|nessus|openvas|burp|faraday|l9scan|leakix`)
	hostingASNs        = map[int]bool{36351: true, 20473: true, 24940: true, 16276: true, 14061: true, 12876: true, 51167: true, 16509: true, 1403: true, 396982: true, 20940: true}
)

type Event struct {
	IP               string
	UserAgent        string
	RequestURI       string
	Method           string
	TTL              int
	Window           int
	MSS              int
	CountryCode      string
	ISPAsn           string
	Reason           string
	Severity         string
	Fingerprint      string
	Evidence         string
	InterArrivalTime float64
	TLSJA3           string
	TLSCipher        string
	HTTPReferer      string
	AcceptLanguage   string
	PostBody         string
	ContentLength    int
	Strikes          int
	CreatedAt        string
}

func PathRisk(path string) float64 {
	if path == "" {
		return 0.0
	}
	low := strings.ToLower(path)
	if honeytokenPatterns.MatchString(low) {
		return 1.0
	}
	if strings.Contains(low, "/admin") || strings.Contains(low, "/login") || strings.Contains(low, "/config") || strings.Contains(low, "/backup") {
		return 0.7
	}
	if strings.Contains(low, "/api") || strings.Contains(low, "/v1") || strings.Contains(low, "/v2") {
		return 0.3
	}
	return 0.1
}

func UARisk(ua string) float64 {
	if ua == "" {
		return 0.5
	}
	low := strings.ToLower(ua)
	if hostileUAPatterns.MatchString(low) {
		return 1.0
	}
	if genericUAPatterns.MatchString(low) {
		return 0.8
	}
	if strings.Contains(low, "mozilla") || strings.Contains(low, "chrome") || strings.Contains(low, "safari") || strings.Contains(low, "firefox") || strings.Contains(low, "edge") || strings.Contains(low, "opera") {
		return 0.0
	}
	return 0.6
}

func GeoRisk(country, asn, reason string) float64 {
	risk := 0.1
	if country == "" || country == "null" {
		risk += 0.2
	}
	if strings.Contains(reason, "TOR") {
		risk += 0.8
	}
	if strings.Contains(reason, "DATACENTER") {
		risk += 0.6
	}
	if strings.HasPrefix(asn, "AS") {
		var asnNum int
		if _, err := fmt.Sscanf(asn[2:], "%d", &asnNum); err == nil && hostingASNs[asnNum] {
			risk += 0.4
		}
	}
	if risk > 1.0 {
		risk = 1.0
	}
	return risk
}

func TimingRisk(interArrival float64, ttl, window int) float64 {
	risk := 0.1
	if ttl == 64 || ttl == 128 || ttl == 255 {
		risk += 0.2
	}
	if window == 64240 || window == 65535 || window == 65536 || window == 29200 || window == 5840 {
		risk += 0.2
	}
	if interArrival == 0 {
		risk += 0.1
	}
	if risk > 1.0 {
		risk = 1.0
	}
	return risk
}

func TemporalFeatures(createdAt string) (float64, float64, float64, float64) {
	var dt time.Time
	if createdAt != "" {
		var err error
		dt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			dt = time.Now().UTC()
		}
	} else {
		dt = time.Now().UTC()
	}
	hour := float64(dt.Hour())
	dayOfWeek := float64(dt.Weekday())
	return math.Sin(2 * math.Pi * hour / 24.0),
		math.Cos(2 * math.Pi * hour / 24.0),
		math.Sin(2 * math.Pi * dayOfWeek / 7.0),
		math.Cos(2 * math.Pi * dayOfWeek / 7.0)
}

func VolumeCoherence(path string, contentLength int) float64 {
	uriLen := len(path)
	total := float64(uriLen + contentLength)
	coherence := total / (config.PHI * 2000.0)
	if coherence < 0.0 {
		coherence = 0.0
	}
	if coherence > 1.0 {
		coherence = 1.0
	}
	return coherence
}

func PhiDivergence(interArrival float64) float64 {
	ia := interArrival
	if ia <= 0 {
		ia = 0.0001
	}
	divergence := math.Abs(math.Log(ia / config.PHI))
	if divergence > 1.0 {
		divergence = 1.0
	}
	return divergence
}

func ExtractFeatures(ev Event) []float64 {
	ttlNorm := math.Min(float64(ev.TTL)/255.0, 1.0)
	windowNorm := math.Min(float64(ev.Window)/65535.0, 1.0)
	mssNorm := math.Min(float64(ev.MSS)/1460.0, 1.0)
	uaScriptScore := UARisk(ev.UserAgent)
	uaLenNorm := math.Min(float64(len(ev.UserAgent))/200.0, 1.0)
	hasReferer := 0.0
	if ev.HTTPReferer != "" {
		hasReferer = 1.0
	}
	pathScore := PathRisk(ev.RequestURI)
	pathLenNorm := math.Min(float64(len(ev.RequestURI))/200.0, 1.0)
	isSensitive := 0.0
	if pathScore > 0.5 {
		isSensitive = 1.0
	}
	geoRisk := GeoRisk(ev.CountryCode, ev.ISPAsn, ev.Reason)
	hasCountry := 0.0
	if ev.CountryCode != "" && ev.CountryCode != "null" {
		hasCountry = 1.0
	}
	asnRisk := 0.0
	if ev.ISPAsn != "" {
		asnRisk = 0.3
	}
	timingRisk := TimingRisk(ev.InterArrivalTime, ev.TTL, ev.Window)
	severityBinary := 0.0
	if ev.Severity == "critical" || ev.Severity == "high" {
		severityBinary = 1.0
	}
	timingBaseline := math.Min(math.Abs(ev.InterArrivalTime-config.PHI)/10.0, 1.0)
	priorStrikesNorm := math.Min(float64(ev.Strikes)/10.0, 1.0)
	hasEvidence := 0.0
	if ev.Evidence != "" {
		hasEvidence = 1.0
	}
	evidenceLenNorm := math.Min(float64(len(ev.Evidence))/500.0, 1.0)
	hasFingerprint := 0.0
	if ev.Fingerprint != "" {
		hasFingerprint = 1.0
	}
	harmonicScore := pathScore*0.3 + uaScriptScore*0.3 + geoRisk*0.2 + timingRisk*0.2

	ja3Risk := 0.5
	if ev.TLSJA3 != "" {
		if strings.Contains(strings.ToLower(ev.TLSJA3), "headless") || ev.TLSJA3 == "unknown" {
			ja3Risk = 1.0
		} else {
			ja3Risk = 0.2
		}
	}
	tlsCipherRisk := 0.5
	if ev.TLSCipher != "" {
		low := strings.ToLower(ev.TLSCipher)
		if strings.Contains(low, "null") || strings.Contains(low, "rc4") || strings.Contains(low, "des") || strings.Contains(low, "tls_1.0") || strings.Contains(low, "tls_1.1") {
			tlsCipherRisk = 0.8
		} else {
			tlsCipherRisk = 0.3
		}
	}
	headerAnomaly := 0.0
	if ev.HTTPReferer == "" {
		headerAnomaly += 0.2
	}
	if ev.AcceptLanguage == "" {
		headerAnomaly += 0.2
	}
	if ev.PostBody == "" && ev.Method == "POST" {
		headerAnomaly += 0.3
	}
	if headerAnomaly > 1.0 {
		headerAnomaly = 1.0
	}
	langRisk := 0.5
	if ev.AcceptLanguage != "" {
		langRisk = 0.1
	}

	hourSin, hourCos, daySin, dayCos := TemporalFeatures(ev.CreatedAt)
	volumeCoherence := VolumeCoherence(ev.RequestURI, ev.ContentLength)
	phiDivergence := PhiDivergence(ev.InterArrivalTime)

	return []float64{
		ttlNorm, windowNorm, mssNorm,
		uaScriptScore, uaLenNorm, hasReferer,
		pathScore, pathLenNorm, isSensitive,
		geoRisk, hasCountry, asnRisk,
		timingRisk, severityBinary, timingBaseline, priorStrikesNorm,
		hasEvidence, evidenceLenNorm, hasFingerprint,
		harmonicScore,
		ja3Risk, tlsCipherRisk, headerAnomaly, langRisk,
		hourSin, hourCos, daySin, dayCos,
		volumeCoherence, phiDivergence,
	}
}


