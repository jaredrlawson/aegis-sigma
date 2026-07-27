package cengine

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/internal/types"
)

var ceMu sync.Mutex

func Classify(features []float64, ip string) (*types.CEngineVerdict, error) {
	payload := map[string]interface{}{
		"features": features,
		"ip":       ip,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	data = append(data, '\n')

	ceMu.Lock()
	defer ceMu.Unlock()

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", config.CEngineHost, config.CEnginePort), config.CEngineTimeout)
		if err != nil {
			lastErr = fmt.Errorf("connect to C engine: %w", err)
			continue
		}
		conn.SetDeadline(time.Now().Add(config.CEngineTimeout))

		if _, err := conn.Write(data); err != nil {
			conn.Close()
			lastErr = fmt.Errorf("send to C engine: %w", err)
			continue
		}

		raw, err := io.ReadAll(conn)
		conn.Close()
		if err != nil && len(raw) == 0 {
			lastErr = fmt.Errorf("read C engine response: %w", err)
			continue
		}
		s := strings.TrimSpace(string(raw))
		s = strings.TrimSuffix(s, `\n`)

		if s == "" {
			lastErr = fmt.Errorf("empty response from C engine")
			continue
		}

		var verdict types.CEngineVerdict
		if err := json.Unmarshal([]byte(s), &verdict); err != nil {
			lastErr = fmt.Errorf("parse C engine response: %w", err)
			continue
		}
		return &verdict, nil
	}
	return nil, lastErr
}
