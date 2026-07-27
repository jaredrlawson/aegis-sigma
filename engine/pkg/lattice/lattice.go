package lattice

import (
	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Record stores an agent's input/output signal pair with a validation status
// and harmonic score. Used to track the Alpha/Beta/Gamma triad signal flow
// and Soul LLM outputs.

// RecordSignal writes one signal transaction to lattice_memory_matrix.
func RecordSignal(agentID int, inputContext, outputSignal, validationStatus string, harmonicScore float64) {
	if validationStatus == "" {
		validationStatus = "pending"
	}
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	d.Exec(`INSERT INTO lattice_memory_matrix
		(agent_id, input_vector_context, output_signal_generated, validation_status, harmonic_score, timestamp)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		agentID, inputContext, outputSignal, validationStatus, harmonicScore)
}

// All returns lattice rows for the dashboard.
func All() []map[string]interface{} {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT id, agent_id, input_vector_context, output_signal_generated,
		validation_status, harmonic_score, timestamp
		FROM lattice_memory_matrix ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, agent int
		var input, output, status, ts string
		var score float64
		rows.Scan(&id, &agent, &input, &output, &status, &score, &ts)
		out = append(out, map[string]interface{}{
			"id":                id,
			"agent_id":          agent,
			"input_context":     input,
			"output_signal":     output,
			"validation_status": status,
			"harmonic_score":    score,
			"timestamp":         ts,
		})
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}

func Count() int {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0
	}
	defer d.Close()
	var n int
	d.QueryRow("SELECT COUNT(*) FROM lattice_memory_matrix").Scan(&n)
	return n
}
