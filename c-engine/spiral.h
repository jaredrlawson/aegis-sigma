/*
 * Aegis-SIGMA Spiral Memory + Phi-Coherence Gate
 *
 * Fibonacci-sequence memory tiers (1, 2, 3, 5, 8, 13) for
 * self-similar state compaction. Phi-ratio threshold filters
 * harmonic signals from disharmonic noise.
 */

#ifndef AEGIS_SPIRAL_H
#define AEGIS_SPIRAL_H

#include <stddef.h>
#include <time.h>

#define PHI_RATIO      1.618033988749895
#define PHI_INV        0.618033988749895
#define SPIRAL_MAX_DEPTH 13

/* Fibonacci sequence for tier capacities */
static const int FIB_SEQ[SPIRAL_MAX_DEPTH] = {
    1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233
};

typedef struct {
    double features[64];
    int    n_features;
    double consensus;
    double auditor_score;
    int    hostile;
    time_t timestamp;
    double resonance;       /* cumulative phi-resonance */
} SpiralNode;

/* Max Fibonacci tier capacity is FIB_SEQ[12] = 233 */
#define SPIRAL_TIER_MAX 233

typedef struct {
    SpiralNode tiers[SPIRAL_MAX_DEPTH][SPIRAL_TIER_MAX];
    int        tier_count[SPIRAL_MAX_DEPTH];
    int        total_samples;
    double     phi_baseline;   /* running harmonic baseline */
    double     total_resonance;
} SpiralMemory;

/* Init / reset */
void spiral_init(SpiralMemory *sm);

/* Record a classification result into the spiral.
 * Folds overflow tiers upward (self-similar compaction). */
void spiral_record(SpiralMemory *sm, const double *features, int n,
                   double consensus, double auditor, int hostile);

/* Evaluate whether a signal aligns with the golden threshold.
 * Returns 1 if harmonic (within phi bounds), 0 if disharmonic. */
int phi_coherence_gate(double signal, double baseline);

/* Recursive self-similar learning — folds input through phi
 * recursion depth levels, producing a compressed resonance score. */
double recursive_spiral_learn(double input, int depth);

/* Compute the spiral's current harmonic baseline from tier 0. */
double spiral_baseline(const SpiralMemory *sm);

/* Get the most recent node (tier 0, slot 0) or NULL. */
const SpiralNode *spiral_latest(const SpiralMemory *sm);

#endif /* AEGIS_SPIRAL_H */
