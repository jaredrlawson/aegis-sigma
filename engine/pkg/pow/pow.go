package pow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
	"github.com/aegis-sigma/engine/pkg/db"
)

// Fibonacci proof-of-work: a visitor must find a nonce so the SHA-256 of
// (challenge || nonce) starts with N zero bits. N is derived from the current
// Fibonacci difficulty index.

var fibSeq = []int{1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597}

// Challenge is what the challenge page hands to the visitor.
type Challenge struct {
	Challenge string `json:"challenge"`
	Difficulty int   `json:"difficulty"`
	Seed       string `json:"seed"`
	Expires    time.Time `json:"expires"`
}

// Issue produces a new POW challenge for a visitor.
func Issue(ip string, strikes int) Challenge {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	seed := randomHex(rnd, 16)
	diff := fibDifficulty(strikes)
	return Challenge{
		Challenge: hashSeed(ip, seed),
		Difficulty: diff,
		Seed:       seed,
		Expires:    time.Now().UTC().Add(300 * time.Second),
	}
}

// Verify checks the visitor's nonce against a previously issued challenge.
// On success it records the energy mined in attack_energy.
func Verify(ip, challenge, seed, nonce string, difficulty int) (bool, int) {
	got := hashAttempt(challenge, nonce)
	bits := countZeroBits(got)
	if bits < difficulty {
		// Power spent but no mint
		recordAttempt(ip, nonce, false, 0, difficulty)
		return false, bits
	}
	energy := fibEnergy(difficulty)
	recordAttempt(ip, nonce, true, energy, difficulty)
	return true, bits
}

// fibDifficulty returns the number of zero bits the visitor must grind.
// Higher strike count → harder PoW (tarpit foes harder).
func fibDifficulty(strikes int) int {
	idx := strikes
	if idx < 0 {
		idx = 0
	}
	if idx >= len(fibSeq) {
		idx = len(fibSeq) - 1
	}
	// Fibonacci-derived difficulty: fib(idx) bits-required is too steep;
	// we use 4 + (idx / 2), capped at 16.
	bits := 4 + idx/2
	if bits < 4 {
		bits = 4
	}
	if bits > 16 {
		bits = 16
	}
	return bits
}

func fibEnergy(difficulty int) float64 {
	// Each successful mint transfers energy equal to the Fibonacci index
	// at the matching difficulty. Energy is "spent" as entropy harvested
	// from the attacker's CPU — used as a virtual tarpit metric.
	if difficulty < 1 || difficulty > len(fibSeq) {
		return 1.0
	}
	return float64(fibSeq[difficulty-1]) / 10.0
}

func recordAttempt(ip, attempt string, isCorrect bool, energy float64, difficulty int) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return
	}
	defer d.Close()
	correct := 0
	if isCorrect {
		correct = 1
	}
	puzzleType := fmt.Sprintf("fibonacci-d%d", difficulty)
	d.Exec(`INSERT INTO attack_energy
		(ip, puzzle_type, difficulty, hash_attempt, is_correct, energy_mined, block_mined, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		ip, puzzleType, difficulty, attempt, correct, energy, 0)
}

// Stats returns summary metrics for the dashboard.
func Stats() (totalAttempts, totalCorrect, totalEnergy float64) {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return 0, 0, 0
	}
	defer d.Close()
	d.QueryRow("SELECT COUNT(*), COALESCE(SUM(is_correct),0), COALESCE(SUM(energy_mined),0) FROM attack_energy").
		Scan(&totalAttempts, &totalCorrect, &totalEnergy)
	return
}

func hashSeed(ip, seed string) string {
	h := sha256.New()
	h.Write([]byte(time.Now().UTC().Format("2006-01-02") + "|" + ip + "|" + seed))
	return hex.EncodeToString(h.Sum(nil))
}

func hashAttempt(challenge, nonce string) string {
	h := sha256.New()
	h.Write([]byte(challenge + "|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

func countZeroBits(hashHex string) int {
	bits := 0
	for _, c := range hashHex {
		v := hexVal(c)
		for i := 3; i >= 0; i-- {
			if (v>>uint(i))&1 == 0 {
				bits++
			} else {
				return bits
			}
		}
	}
	return bits
}

func hexVal(c rune) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return 0
	}
}

func randomHex(rnd *rand.Rand, n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[rnd.Intn(16)]
	}
	return strings.TrimSpace(string(b))
}

// FibEnergy returns the energy mined for a given difficulty level.
// Public wrapper so the Shield can call it.
func FibEnergy(difficulty int) float64 {
	return fibEnergy(difficulty)
}

// RecordMined records a successful PoW solve in attack_energy.
// Public wrapper so the Shield can call it.
func RecordMined(ip string, difficulty int, hash string, energy float64) {
	recordAttempt(ip, hash, true, energy, difficulty)
}

// StatsDetailed returns per-difficulty breakdown for the dashboard.
func StatsDetailed() []map[string]interface{} {
	d, err := db.Open(config.BrainDB)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer d.Close()
	rows, err := d.Query(`SELECT puzzle_type, COUNT(*), COALESCE(SUM(is_correct),0), COALESCE(SUM(energy_mined),0)
		FROM attack_energy GROUP BY puzzle_type ORDER BY puzzle_type`)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var ptype string
		var cnt, correct int
		var energy float64
		rows.Scan(&ptype, &cnt, &correct, &energy)
		out = append(out, map[string]interface{}{
			"puzzle_type": ptype,
			"attempts":    cnt,
			"solved":      correct,
			"energy":      energy,
		})
	}
	if out == nil {
		return []map[string]interface{}{}
	}
	return out
}
