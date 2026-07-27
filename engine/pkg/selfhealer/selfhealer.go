package selfhealer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

var (
	checkInterval   = 60 * time.Second
	restartCooldown = 5 * time.Second
	maxRestarts     = 3
	window          = 10 * time.Minute
	logPath         = "/var/log/aegis/selfhealer.log"
)

type serviceState struct {
	mu               sync.Mutex
	restartCount     int
	lastRestart      time.Time
	windowStart      time.Time
	consecutiveFails int
	restartInFlight  bool
	lastStatusChange time.Time
}

var stateMap = struct {
	sync.Mutex
	m map[string]*serviceState
}{m: make(map[string]*serviceState)}

func Start() {
	for {
		time.Sleep(checkInterval)
		HealthCheck()
	}
}

func HealthCheck() {
	for _, svc := range config.MonitoredServices {
		if !isHealthy(svc) {
			heal(svc)
		}
	}
}

func isHealthy(svc string) bool {
	result, err := exec.Command("systemctl", "is-active", svc).CombinedOutput()
	active := err == nil && strings.TrimSpace(string(result)) == "active"
	if !active {
		return false
	}
	// Allow services a grace period after a restart before port-checking them.
	stateMap.Lock()
	st, ok := stateMap.m[svc]
	stateMap.Unlock()
	if ok && st != nil {
		st.mu.Lock()
		inGrace := st.restartInFlight || time.Since(st.lastStatusChange) < 30*time.Second
		st.mu.Unlock()
		if inGrace {
			return true
		}
	}
	// Also verify the port this service should listen on
	port := servicePort(svc)
	if port > 0 {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			log(fmt.Sprintf("[SELF-HEALER] %s systemd active but port %d unreachable", svc, port))
			return false
		}
		conn.Close()
	}
	return true
}

func servicePort(svc string) int {
	// Map service names to their primary listening ports
	ports := map[string]int{
		"aegis-shield-go": 3000,
		"aegis-trap-go":   3001,
		"aegis-soul-go":   3007,
		"aegis-geoip-go":  4040,
		"aegis-dashboard": 9001,
		"aegis-data-bridge": 8085,
		"aegis-c":         20129,
		"aegis-auditor":   20130,
	}
	if p, ok := ports[svc]; ok {
		return p
	}
	return 0
}

func heal(svc string) {
	stateMap.Lock()
	st, ok := stateMap.m[svc]
	if !ok {
		st = &serviceState{windowStart: time.Now()}
		stateMap.m[svc] = st
	}
	stateMap.Unlock()

	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	if now.Sub(st.windowStart) > window {
		st.restartCount = 0
		st.windowStart = now
		st.consecutiveFails = 0
	}

	// Don't double-trigger a restart already in progress.
	if st.restartInFlight {
		return
	}

	if st.restartCount >= maxRestarts {
		if st.consecutiveFails%10 == 0 {
			log(fmt.Sprintf("[SELF-HEALER] %s circuit open: too many restarts, skipping", svc))
		}
		st.consecutiveFails++
		return
	}

	st.restartCount++
	st.lastRestart = now
	st.restartInFlight = true
	attempt := st.restartCount
	log(fmt.Sprintf("[SELF-HEALER] %s is down (attempt %d/%d), restarting...", svc, attempt, maxRestarts))

	go func() {
		time.Sleep(restartCooldown)
		output, err := exec.Command("systemctl", "restart", svc).CombinedOutput()

		st.mu.Lock()
		st.restartInFlight = false
		st.lastStatusChange = time.Now()
		if err != nil {
			st.consecutiveFails++
			st.mu.Unlock()
			log(fmt.Sprintf("[SELF-HEALER] %s restart failed: %v (%s)", svc, err, strings.TrimSpace(string(output))))
			return
		}
		st.mu.Unlock()
		log(fmt.Sprintf("[SELF-HEALER] %s restarted successfully", svc))
	}()
}

func log(msg string) {
	fmt.Println(msg)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(fmt.Sprintf("[%s] %s\n", time.Now().UTC().Format(time.RFC3339), msg))
}
