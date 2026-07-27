package abuse

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

func SendAbuseReport(ip, asn, isp, country, attackType, evidence string) error {
	report := generateAbuseEmail(ip, asn, isp, country, attackType, evidence)
	logAbuseReport(report)
	return nil
}

func generateAbuseEmail(ip, asn, isp, country, attackType, evidence string) string {
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	return fmt.Sprintf("ABUSE REPORT\nDate: %s\nIP: %s\nASN: %s\nISP: %s\nCountry: %s\nType: %s\nEvidence: %s\nCase: AEGIS-%d\n",
		ts, ip, asn, isp, country, attackType, evidence, time.Now().Unix())
}

func logAbuseReport(report string) {
	f, err := os.OpenFile(config.EvidenceDir+"/abuse-reports.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(report + "\n---\n")
}

func GetAbuseStats() map[string]interface{} {
	count := 0
	data, _ := os.ReadFile(config.EvidenceDir + "/abuse-reports.log")
	if data != nil {
		count = strings.Count(string(data), "ABUSE REPORT")
	}
	return map[string]interface{}{"total_reports": count, "last_check": time.Now().Format(time.RFC3339)}
}
