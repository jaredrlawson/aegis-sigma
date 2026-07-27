/*
 * Aegis-SIGMA Groq 120B Teacher Bridge
 *
 * Sends classification context to Groq's 120B LLM API as the
 * "teacher" for the C engine's online learner. The teacher
 * provides authoritative benign/hostile labels with reasoning,
 * using Fibonacci-windowed context from the spiral memory.
 *
 * API: POST https://api.groq.com/openai/v1/chat/completions
 * Model: groq/llama-3.3-70b-versatile (fastest 120B-class on Groq)
 */

#ifndef AEGIS_GROQ_TEACHER_H
#define AEGIS_GROQ_TEACHER_H

#include "spiral.h"

#define GROQ_API_URL "https://api.groq.com/openai/v1/chat/completions"
#define GROQ_MODEL   "openai/gpt-oss-120b"
#define GROQ_MAX_CONTEXT 2048
#define GROQ_BUFFER_SIZE 4096

typedef struct {
    int    hostile;        /* teacher verdict: 0=benign, 1=hostile */
    double confidence;     /* 0.0 - 1.0 */
    char   reasoning[512]; /* teacher's explanation */
    int    valid;          /* 1 if we got a parseable response */
} GroqVerdict;

typedef struct {
    char api_key[128];
    int  enabled;
    int  cooldown_sec;     /* rate-limit cooldown between calls */
    time_t last_call;
    int    total_calls;
    int    total_errors;
} GroqTeacher;

/* Initialize the teacher with API key */
void groq_teacher_init(GroqTeacher *gt, const char *api_key);

/* Query the Groq 120B teacher for a verdict on a classification.
 * Uses Fibonacci-windowed context from spiral memory.
 * Returns 0 on success, -1 on error/rate-limit. */
int groq_teacher_query(GroqTeacher *gt, const SpiralMemory *sm,
                       const double *features, int n_features,
                       double c_engine_consensus, int c_engine_hostile,
                       GroqVerdict *out);

#endif /* AEGIS_GROQ_TEACHER_H */
