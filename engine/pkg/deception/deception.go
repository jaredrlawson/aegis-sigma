package deception

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

const markOfCainSecret = "aegis-sigma-mark-of-cain"

func GenerateMarkOfCain(ip, ua string) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	payload := ip + ":" + ua + ":" + ts
	h := hmac.New(sha256.New, []byte(markOfCainSecret))
	h.Write([]byte(payload))
	return payload + ":" + fmt.Sprintf("%x", h.Sum(nil))[:32]
}

func VerifyMarkOfCain(cookieVal, ip, ua string) bool {
	parts := strings.Split(cookieVal, ":")
	if len(parts) < 4 {
		return false
	}
	payload := parts[0] + ":" + parts[1] + ":" + parts[2]
	h := hmac.New(sha256.New, []byte(markOfCainSecret))
	h.Write([]byte(payload))
	expected := fmt.Sprintf("%x", h.Sum(nil))[:32]
	return parts[3] == expected
}
