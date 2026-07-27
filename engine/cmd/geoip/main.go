package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/oschwald/maxminddb-golang"
)

var reader *maxminddb.Reader
var asnReader *maxminddb.Reader

func main() {
	mmdbPath := os.Getenv("GEOIP_MMDB")
	if mmdbPath == "" {
		mmdbPath = "/var/lib/GeoIP/Merged-IP.mmdb"
	}
	var err error
	reader, err = openMMDB(mmdbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[GEOIP] mmdb not available (%v), falling back to whois\n", err)
	}

	// Also load GeoLite2-ASN.mmdb for richer ASN/ISP data if available
 asnPath := "/var/lib/GeoIP/GeoLite2-ASN.mmdb"
	if _, err2 := os.Stat(asnPath); err2 == nil {
		asnReader, err = openMMDB(asnPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[GEOIP] ASN mmdb load failed: %v\n", err)
		} else {
			fmt.Println("[GEOIP] Loaded GeoLite2-ASN.mmdb")
		}
	}

	fmt.Printf("[GEOIP] Go GeoIP on :%d\n", config.GeoIPPort)
	http.HandleFunc("/", handleLookup)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	http.ListenAndServe(fmt.Sprintf(":%d", config.GeoIPPort), nil)
}

func openMMDB(path string) (*maxminddb.Reader, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		gzPath := path + ".gz"
		if _, err2 := os.Stat(gzPath); err2 == nil {
			path = gzPath
		} else if _, err3 := os.Stat("/tmp/GeoLite2-City/GeoLite2-City.mmdb"); err3 == nil {
			path = "/tmp/GeoLite2-City/GeoLite2-City.mmdb"
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, 2)
	f.Read(buf)
	f.Seek(0, 0)

	if buf[0] == 0x1f && buf[1] == 0x8b {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gr.Close()
		data, err := io.ReadAll(gr)
		if err != nil {
			return nil, fmt.Errorf("read gzip: %w", err)
		}
		return maxminddb.FromBytes(data)
	}

	return maxminddb.Open(path)
}

func handleLookup(w http.ResponseWriter, r *http.Request) {
	ipStr := strings.TrimPrefix(r.URL.Path, "/")
	if ipStr == "" || ipStr == "health" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid ip"})
		return
	}

	var result map[string]interface{}
	if reader != nil {
		result = mmdbLookup(ip, ipStr)
	} else {
		result = whoisLookup(ipStr)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		IsoCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
	Subdivisions []struct {
		IsoCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

type asnRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

type nestedASN struct {
	ASN struct {
		Number uint   `maxminddb:"autonomous_system_number"`
		Name   string `maxminddb:"autonomous_system_organization"`
		Domain string `maxminddb:"as_domain"`
	} `maxminddb:"asn"`
	Proxy struct {
		IsProxy     bool `maxminddb:"is_proxy"`
		IsVPN       bool `maxminddb:"is_vpn"`
		IsTor       bool `maxminddb:"is_tor"`
		IsHosting   bool `maxminddb:"is_hosting"`
		IsCDN       bool `maxminddb:"is_cdn"`
		IsAnonymous bool `maxminddb:"is_anonymous"`
	} `maxminddb:"proxy"`
}

func mmdbLookup(ip net.IP, ipStr string) map[string]interface{} {
	result := map[string]interface{}{
		"ip": ipStr, "asn": "N/A", "asn_name": "N/A",
		"country": "N/A", "city": "", "hosting": false,
		"lat": 0.0, "lon": 0.0,
	}

	var city cityRecord
	if err := reader.Lookup(ip, &city); err != nil {
		result["country"] = "Unknown"
		return result
	}

	result["country"] = city.Country.IsoCode
	if city.Country.IsoCode == "" {
		result["country"] = city.Country.Names["en"]
	}
	result["city"] = city.City.Names["en"]
	result["lat"] = city.Location.Latitude
	result["lon"] = city.Location.Longitude
	if len(city.Subdivisions) > 0 {
		result["region"] = city.Subdivisions[0].Names["en"]
		result["region_code"] = city.Subdivisions[0].IsoCode
	}
	result["timezone"] = city.Location.TimeZone
	result["postal_code"] = city.Postal.Code

	// ASN and proxy lookup from merged MMDB (nested fields)
	var nested nestedASN
	if err := reader.Lookup(ip, &nested); err == nil {
		if nested.ASN.Number > 0 {
			result["asn"] = fmt.Sprintf("%d", nested.ASN.Number)
			result["asn_name"] = nested.ASN.Name
		}
		result["is_proxy"] = nested.Proxy.IsProxy
		result["is_vpn"] = nested.Proxy.IsVPN
		result["is_tor"] = nested.Proxy.IsTor
		result["is_hosting"] = nested.Proxy.IsHosting || result["hosting"].(bool)
		result["is_cdn"] = nested.Proxy.IsCDN
		result["is_anonymous"] = nested.Proxy.IsAnonymous
	}

	// Enrich from GeoLite2-ASN.mmdb if available (richer ISP data)
	if asnReader != nil {
		var asnData struct {
			Number uint   `maxminddb:"autonomous_system_number"`
			Name   string `maxminddb:"autonomous_system_organization"`
			Domain string `maxminddb:"as_domain"`
		}
		if err := asnReader.Lookup(ip, &asnData); err == nil && asnData.Number > 0 {
			if result["asn"] == "N/A" || result["asn"] == "" {
				result["asn"] = fmt.Sprintf("%d", asnData.Number)
			}
			if result["asn_name"] == "N/A" || result["asn_name"] == "" {
				result["asn_name"] = asnData.Name
			}
		}
	}

	return result
}

var whoisFail = map[string]bool{}

func whoisLookup(ip string) map[string]interface{} {
	result := map[string]interface{}{
		"ip": ip, "asn": "N/A", "asn_name": "N/A", "country": "N/A", "city": "", "hosting": false,
		"lat": 0.0, "lon": 0.0,
	}
	if whoisFail[ip] {
		return result
	}
	out, err := exec.Command("whois", "-h", "whois.cymru.com", "-p", "43", ip).CombinedOutput()
	if err != nil {
		whoisFail[ip] = true
		return result
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 1 {
		parts := strings.Split(lines[1], "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) > 2 {
			asnName := parts[2]
			result["asn"] = parts[0]
			result["asn_name"] = asnName
			if idx := strings.LastIndex(asnName, ","); idx != -1 {
				result["country"] = strings.TrimSpace(asnName[idx+1:])
			}
		}
	}
	return result
}
