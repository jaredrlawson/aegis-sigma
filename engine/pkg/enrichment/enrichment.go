package enrichment

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var cache = map[string]cacheEntry{}

type cacheEntry struct {
	data map[string]string
	ts   time.Time
}

func GetGeoIP(ip string) map[string]string {
	if e, ok := cache[ip]; ok && time.Since(e.ts) < time.Hour {
		return e.data
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:4040/" + ip)
	if err != nil {
		return map[string]string{"country": "XX", "city": "", "asn": "", "isp": "Unknown"}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var d map[string]interface{}
	json.Unmarshal(body, &d)
	result := map[string]string{
		"country": getString(d, "country", "XX"),
		"city":    getString(d, "city", ""),
		"region":  getString(d, "region", ""),
		"asn":     getString(d, "asn", ""),
		"isp":     getString(d, "asn_name", getString(d, "isp", "Unknown")),
		"zip":     getString(d, "postal_code", ""),
		"lat":     getFloat(d, "lat", "0"),
		"lon":     getFloat(d, "lon", "0"),
	}
	cache[ip] = cacheEntry{data: result, ts: time.Now()}
	return result
}

func getString(m map[string]interface{}, key, def string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func getFloat(m map[string]interface{}, key, def string) string {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return fmt.Sprintf("%.6f", f)
		}
	}
	return def
}
