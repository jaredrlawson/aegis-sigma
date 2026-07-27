package threatfeed

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

type ThreatEvent struct {
	Timestamp string  `json:"timestamp"`
	IP        string  `json:"ip"`
	Actor     string  `json:"actor"`
	Consensus float64 `json:"consensus"`
	Severity  string  `json:"severity"`
	Reason    string  `json:"reason"`
	Country   string  `json:"country"`
}

var (
	threatFeed = make(chan ThreatEvent, 1000)
	clients    = map[chan ThreatEvent]bool{}
	clientsMu  sync.RWMutex
)

func PushEvent(event ThreatEvent) {
	select {
	case threatFeed <- event:
	default:
	}
}

func Subscribe() chan ThreatEvent {
	ch := make(chan ThreatEvent, 100)
	clientsMu.Lock()
	clients[ch] = true
	clientsMu.Unlock()
	return ch
}

func Unsubscribe(ch chan ThreatEvent) {
	clientsMu.Lock()
	delete(clients, ch)
	clientsMu.Unlock()
	close(ch)
}

func FanOut() {
	for event := range threatFeed {
		clientsMu.RLock()
		for ch := range clients {
			select {
			case ch <- event:
			default:
			}
		}
		clientsMu.RUnlock()
		logThreatEvent(event)
	}
}

func logThreatEvent(event ThreatEvent) {
	f, err := os.OpenFile(config.EvidenceDir+"/threat-feed.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	data, _ := json.Marshal(event)
	f.Write(data)
	f.WriteString("\n")
}

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	ch := Subscribe()
	defer Unsubscribe(ch)

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func GetRecentThreats(n int) []ThreatEvent {
	f, err := os.Open(config.EvidenceDir + "/threat-feed.jsonl")
	if err != nil {
		return nil
	}
	defer f.Close()

	var events []ThreatEvent
	decoder := json.NewDecoder(f)
	for decoder.More() {
		var event ThreatEvent
		if decoder.Decode(&event) == nil {
			events = append(events, event)
		}
	}

	if len(events) > n {
		events = events[len(events)-n:]
	}
	return events
}
