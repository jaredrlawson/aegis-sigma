/*
 * Aegis-SIGMA Spiral Memory + Phi-Coherence Gate
 *
 * Fibonacci-sequence memory tiers (1, 2, 3, 5, 8, 13) for
 * self-similar state compaction. Phi-ratio threshold filters
 * harmonic signals from disharmonic noise.
 */

#include "spiral.h"
#include <string.h>
#include <math.h>

void spiral_init(SpiralMemory *sm) {
    if (!sm) return;
    memset(sm, 0, sizeof(SpiralMemory));
    sm->phi_baseline = 0.5; /* neutral starting point */
}

int phi_coherence_gate(double signal, double baseline) {
    if (baseline < 0.0001) baseline = 0.0001;
    double ratio = signal / baseline;
    if (ratio >= PHI_INV && ratio <= PHI_RATIO) {
        return 1; /* harmonic — within phi bounds */
    }
    return 0; /* disharmonic — outside golden threshold */
}

double recursive_spiral_learn(double input, int depth) {
    if (depth <= 1) {
        return input * PHI_INV;
    }
    double prev = recursive_spiral_learn(input, depth - 1);
    return (input + prev) * PHI_INV;
}

static void spiral_fold_tier(SpiralMemory *sm, int tier) {
    if (tier >= SPIRAL_MAX_DEPTH - 1) return;
    int next = tier + 1;

    /* Compute the averaged state from this tier */
    int count = sm->tier_count[tier];
    if (count == 0) return;

    double avg_consensus = 0.0, avg_auditor = 0.0, avg_resonance = 0.0;
    double avg_features[64];
    int n_feat = 0;
    memset(avg_features, 0, sizeof(avg_features));

    for (int i = 0; i < count; i++) {
        SpiralNode *n = &sm->tiers[tier][i];
        avg_consensus += n->consensus;
        avg_auditor   += n->auditor_score;
        avg_resonance += n->resonance;
        if (n->n_features > 0 && n_feat == 0) n_feat = n->n_features;
        for (int f = 0; f < n->n_features && f < 64; f++) {
            avg_features[f] += n->features[f];
        }
    }
    avg_consensus /= count;
    avg_auditor   /= count;
    avg_resonance /= count;
    for (int f = 0; f < n_feat; f++) {
        avg_features[f] /= count;
    }

    /* Recursive self-similar compression */
    avg_resonance = recursive_spiral_learn(avg_resonance, 2);

    /* Compact into next tier if there's room, otherwise cascade-fold */
    if (sm->tier_count[next] < FIB_SEQ[next]) {
        SpiralNode *dest = &sm->tiers[next][sm->tier_count[next]];
        memcpy(dest->features, avg_features, sizeof(avg_features));
        dest->n_features   = n_feat;
        dest->consensus    = avg_consensus;
        dest->auditor_score = avg_auditor;
        dest->hostile      = (avg_consensus > 0.618) ? 1 : 0;
        dest->timestamp    = time(NULL);
        dest->resonance    = avg_resonance;
        sm->tier_count[next]++;
    } else {
        spiral_fold_tier(sm, next);
    }

    /* Clear the folded tier */
    sm->tier_count[tier] = 0;
}

void spiral_record(SpiralMemory *sm, const double *features, int n,
                   double consensus, double auditor, int hostile) {
    if (!sm || !features || n == 0) return;

    int idx = sm->tier_count[0];

    /* If tier 0 is full, fold it up */
    if (idx >= FIB_SEQ[0]) {
        spiral_fold_tier(sm, 0);
        idx = sm->tier_count[0];
    }

    SpiralNode *node = &sm->tiers[0][idx];
    memcpy(node->features, features, sizeof(double) * (size_t)(n < 64 ? n : 64));
    node->n_features    = n;
    node->consensus     = consensus;
    node->auditor_score = auditor;
    node->hostile       = hostile;
    node->timestamp     = time(NULL);

    /* Compute phi-resonance: how well this signal aligns with baseline */
    double coherence = phi_coherence_gate(consensus, sm->phi_baseline);
    node->resonance = coherence ? consensus * PHI_INV : consensus * PHI_RATIO;

    sm->tier_count[0]++;
    sm->total_samples++;
    sm->total_resonance += node->resonance;

    /* Update baseline using exponential moving average */
    sm->phi_baseline = sm->phi_baseline * 0.95 + consensus * 0.05;
}

double spiral_baseline(const SpiralMemory *sm) {
    if (!sm) return 0.5;
    return sm->phi_baseline;
}

const SpiralNode *spiral_latest(const SpiralMemory *sm) {
    if (!sm || sm->tier_count[0] == 0) return NULL;
    return &sm->tiers[0][sm->tier_count[0] - 1];
}
