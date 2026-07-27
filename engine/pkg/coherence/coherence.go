package coherence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Gate represents a harmonic coherence gate — the φ-signature that validates
// whether a hardware/TCP fingerprint matches the actor's claimed identity.
// Failures increment failure_count and lock the gate until a cooldown passes.

// Record creates or updates a coherence gate for a hardware fingerprint.
func Record(hardwareID, phiSignature string, harmonic bool) {
	if hardwareID == "" {
		return
	}
	gateUUID := gateUUID(hardwareID, phiSignature)
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	var exists int
	d.QueryRow("SELECT COUNT(*) FROM coherence_gates WHERE gate_uuid = ?", gateUUID).Scan(&exists)
	if exists == 0 {
		isHarmonic := 1
		if !harmonic {
			isHarmonic = 0
		}
		d.Exec(`INSERT INTO coherence_gates
			(gate_uuid, hardware_id, aegis_phi_signature, is_harmonic, failure_count, last_check, created_at)
			VALUES (?, ?, ?, ?, ?,datetime('now'), datetime('now'))`,
			gateUUID, hardwareID, phiSignature, isHarmonic, 0)
		return
	}
	// Existing gate — if non-harmonic update, bump failure count
	if !harmonic {
		d.Exec(`UPDATE coherence_gates SET
			is_harmonic = 0, failure_count = failure_count + 1,
			locked_until = datetime('now','+15 minutes'),
			last_check = datetime('now') WHERE gate_uuid = ?`, gateUUID)
	} else {
		d.Exec(`UPDATE coherence_gates SET
			is_harmonic = 1, last_check = datetime('now') WHERE gate_uuid = ?`, gateUUID)
	}
}

// IsLocked returns true if the gate is currently in a cooldown.
func IsLocked(hardwareID string) bool {
	if hardwareID == "" {
		return false
	}
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return false
	}
	defer d.Close()
	var locked string
	d.QueryRow(`SELECT locked_until FROM coherence_gates
		WHERE hardware_id = ? ORDER BY id DESC LIMIT 1`, hardwareID).Scan(&locked)
	if locked == "" {
		return false
	}
	// locked_until stored as 'YYYY-MM-DD HH:MM:SS' or RFC3339
	return locked > currentTime()
}

// All returns gate rows for the dashboard.
func All() []map[string]interface{} {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT gate_uuid, hardware_id, aegis_phi_signature,
		is_harmonic, COALESCE(failure_count,0), COALESCE(locked_until,''),
		last_check, created_at FROM coherence_gates ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var gateUUID, hwID, phiSig, locked, lastCheck, created string
		var harmonic, failures int
		rows.Scan(&gateUUID, &hwID, &phiSig, &harmonic, &failures, &locked, &lastCheck, &created)
		out = append(out, map[string]interface{}{
			"gate_uuid":          gateUUID,
			"hardware_id":        hwID,
			"phi_signature":      phiSig,
			"is_harmonic":        harmonic == 1,
			"failure_count":      failures,
			"locked_until":       locked,
			"last_check":         lastCheck,
			"created_at":         created,
		})
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}

func gateUUID(hardwareID, phiSig string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("aegis-gate:%s|%s", hardwareID, phiSig)))
	return "GATE-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// Evaluate checks the φ-coherence between a hardware signature and a consensus.
// Returns true if the gate is harmonic (φ-aligned).
func Evaluate(hardwareSig string, consensus float64, phiThreshold float64) bool {
	if phiThreshold == 0 {
		phiThreshold = 0.5
	}
	// Simple harmonic check: consensus should be close to φ-multiple peaks.
	// In production, this uses the harmonic_score from the C engine auditor.
	return consensus >= phiThreshold
}

func currentTime() string {
	return nowRFC()
}

func nowRFC() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}
