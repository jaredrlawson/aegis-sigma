/*
 * Aegis-SIGMA Shield/Soul Gateway ML
 * Real-time ingress threat consensus engine (C binary, VPS1).
 *
 * 4-model pipeline: Reflex, Shield (LightGBM), Soul (Isolation Forest),
 * Lead Hunter (linear), Auditor (Phi-weighted consensus).
 * Lead weights persist to lead_weights.json with maturity lock.
 *
 * Fibonacci Spiral Memory: self-similar state compaction through
 * phi-aligned tiers (1, 2, 3, 5, 8, 13 samples per tier).
 *
 * Groq 120B Teacher: authoritative LLM labels for online learning.
 */

#ifndef AEGIS_SHIELD_SOUL_H
#define AEGIS_SHIELD_SOUL_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include "spiral.h"
#include "groq_teacher.h"

#define AEGIS_OK 0
#define AEGIS_ERR -1

/* Phi-weighted consensus coefficients -- sum = 1.0 */
#define PHI_W_SHIELD 0.382
#define PHI_W_SOUL   0.236
#define PHI_W_LEAD   0.236
#define PHI_W_REFLEX 0.146

#define AEGIS_RING_BUFFER_SIZE 10000
#define AEGIS_IP_STR_LEN 40

typedef struct {
    char ip[AEGIS_IP_STR_LEN];
    double timestamp;
    double inter_arrival;
    uint32_t count;
} aegis_connection_t;

typedef struct {
    aegis_connection_t *buffer;
    size_t size;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mutex;
} aegis_ring_buffer_t;

typedef struct {
    double reflex_score;
    double shield_score;
    double soul_score;
    double lead_score;
    double consensus_score;
    double auditor_score;
    int is_hostile;
} aegis_verdict_t;

int  aegis_engine_init(const char *shield_model_path, const char *soul_model_path);
void aegis_engine_shutdown(void);

int  aegis_ring_init(aegis_ring_buffer_t *rb, size_t size);
void aegis_ring_free(aegis_ring_buffer_t *rb);
int  aegis_ring_push(aegis_ring_buffer_t *rb, const aegis_connection_t *rec);
int  aegis_ring_find(aegis_ring_buffer_t *rb, const char *ip, aegis_connection_t *out);

double aegis_reflex_score(const double *features, size_t n);
double aegis_shield_score(const double *features, size_t n);
double aegis_soul_score(const double *features, size_t n);
double aegis_lead_score(const double *features, size_t n);
double aegis_auditor_consensus(const aegis_verdict_t *v);
void   aegis_gradient_step(double *weights, const double *features, size_t n, double target, double predicted);
aegis_verdict_t aegis_classify(const double *features, size_t n);

void aegis_lead_weights_save(const char *path);
void aegis_lead_weights_load(const char *path);

int  aegis_start_server(int port);
void aegis_stop_server(int fd);

#endif
