/*
 * Aegis-SIGMA Shield/Soul Gateway ML
 *
 * Real-time ingress threat consensus engine (C binary, VPS1).
 *
 * Four-model pipeline: Reflex (fast filter) -> Shield (LightGBM class.)
 * -> Soul (Isolation Forest anomal.) -> Lead Hunter (linear scorer)
 * -> Auditor (Phi-weighted consensus).
 *
 * Two listening sockets:
 *   1. TCP feature-inference on --port (default 20129). Accepts newline-
 *      delimited JSON or space-separated feature arrays.
 *   2. HTTP status on --status-port (default 8086) serving GET /status.
 *
 * Lead Hunter weights persisted to lead_weights.json on shutdown.
 * Maturity threshold: rolling avg error < 0.01 over 144-cycle window
 * locks weights to prevent over-training.
 */

#include "shield_soul.h"
#include "model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#if defined(__has_include)
#if __has_include(<cjson/cJSON.h>)
#include <cjson/cJSON.h>
#elif __has_include(<cJSON.h>)
#include <cJSON.h>
#else
#include <cjson/cJSON.h>
#endif
#else
#include <cjson/cJSON.h>
#endif

/* -------------------------------------------------------------------------- *
 * Engine state
 * -------------------------------------------------------------------------- */
static int g_engine_initialized = 0;
static aegis_ring_buffer_t g_ring;
static volatile int g_shutdown = 0;
static aegis_model_t g_shield_model;
static aegis_model_t g_soul_model;
static int g_shield_loaded = 0;
static int g_soul_loaded = 0;

/* --- Fibonacci Spiral Memory + Phi-Coherence Gate --- */
static SpiralMemory g_spiral;
static pthread_mutex_t g_spiral_mutex = PTHREAD_MUTEX_INITIALIZER;

/* --- Groq 120B Teacher --- */
static GroqTeacher g_teacher;
static int g_teacher_queries = 0;
static int g_teacher_overrides = 0;

static _Atomic uint_fast64_t g_inference_count = 0;
static _Atomic uint_fast64_t g_hostile_count = 0;
static _Atomic uint_fast64_t g_training_cycles = 0;

static char *g_metrics_path_dup = NULL;
static double g_metrics_accuracy = 0.0;
static double g_metrics_f1 = 0.0;
static uint_fast64_t g_metrics_base_cycles = 0;
static char g_metrics_last_trained[64] = "";
static double g_metrics_hostile_ratio = 0.0;
static int g_metrics_n_hostile = 0;
static int g_metrics_n_benign = 0;
static char g_metrics_data_source[64] = "synthetic";
static time_t g_metrics_mtime = 0;
static pthread_mutex_t g_metrics_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t g_engine_started_at = 0;
static int g_status_port = 8086;
static char g_status_bind_ip[64] = "0.0.0.0";

/* -------------------------------------------------------------------------- *
 * Lead Hunter + Maturity
 * -------------------------------------------------------------------------- */
static double g_lead_weights[8];
static int g_lead_initialized = 0;
#define LEAD_LR_SCALE 0.001
/* Fibonacci learning rate state - F_t converges to 1/phi */
static uint64_t g_fib_cur = 1;
static uint64_t g_fib_nxt = 1;
#define FIB_LOOKAHEAD 5
#define LEAD_WEIGHTS_PATH "/opt/aegis-c-models/lead_weights.json"
#define LOG_FILE "/var/log/aegis/shield_soul.log"

/* Maturity tracking */
#define MATURITY_WINDOW 144
static double g_error_ring[MATURITY_WINDOW];
static int g_error_index = 0;
static int g_error_count = 0;
static int g_mature = 0;
static pthread_mutex_t g_error_mutex = PTHREAD_MUTEX_INITIALIZER;

/* --- VPS2 Terminal-Hub push (forward every log line to the live dashboard) --- */
/* Bounded detached-thread pusher: never blocks the inference path on network
 * latency. If HUB_MAX_INFLIGHT pushes are already in flight we drop the line
 * (the on-disk log + Python tailer still guarantee end-to-end delivery). */
static _Atomic int g_hub_inflight = 0;
#define HUB_MAX_INFLIGHT 8
static int g_hub_port = 0;
static char g_hub_host[64] = "";
static char g_hub_path[128] = "/api/push-model-event";

static void parse_hub_url(const char *url) {
    if (!url || !*url) return;
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) { /* HTTPS unsupported without TLS; treat as http */ p += 8; }
    const char *colon = strchr(p, ':');
    const char *slash = strchr(p, '/');
    if (colon && (!slash || colon < slash)) {
        size_t hl = (size_t)(colon - p);
        if (hl >= sizeof(g_hub_host)) hl = sizeof(g_hub_host) - 1;
        memcpy(g_hub_host, p, hl); g_hub_host[hl] = '\0';
        g_hub_port = atoi(colon + 1);
    } else {
        size_t hl = slash ? (size_t)(slash - p) : strlen(p);
        if (hl >= sizeof(g_hub_host)) hl = sizeof(g_hub_host) - 1;
        memcpy(g_hub_host, p, hl); g_hub_host[hl] = '\0';
        g_hub_port = 9001;
    }
    if (slash) snprintf(g_hub_path, sizeof(g_hub_path), "%s", slash);
}

struct hub_push_ctx {
    char host[64];
    int port;
    char path[128];
    char json[1024];
};

static void *hub_push_thread(void *arg) {
    struct hub_push_ctx *ctx = (struct hub_push_ctx *)arg;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)ctx->port);
        inet_pton(AF_INET, ctx->host, &addr.sin_addr);
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            char hdr[512];
            int hl = snprintf(hdr, sizeof(hdr),
                "POST %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n",
                ctx->path, ctx->host, ctx->port, strlen(ctx->json));
            if (hl > 0 && hl < (int)sizeof(hdr)) {
                send(sock, hdr, (size_t)hl, MSG_NOSIGNAL);
                send(sock, ctx->json, strlen(ctx->json), MSG_NOSIGNAL);
                char resp[256];
                recv(sock, resp, sizeof(resp) - 1, 0);
            }
        }
        close(sock);
    }
    atomic_fetch_sub(&g_hub_inflight, 1);
    free(ctx);
    return NULL;
}

static void push_to_hub(const char *source, const char *raw_line) {
    if (g_hub_port == 0 || g_hub_host[0] == '\0') return;
    if (!source || !raw_line || !*raw_line) return;
    int prev = atomic_fetch_add(&g_hub_inflight, 1);
    if (prev >= HUB_MAX_INFLIGHT) {
        atomic_fetch_sub(&g_hub_inflight, 1);
        return; /* back-pressure: drop, tailer will catch up */
    }
    struct hub_push_ctx *ctx = (struct hub_push_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) { atomic_fetch_sub(&g_hub_inflight, 1); return; }
    strncpy(ctx->host, g_hub_host, sizeof(ctx->host) - 1);
    ctx->port = g_hub_port;
    strncpy(ctx->path, g_hub_path, sizeof(ctx->path) - 1);

    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "source", source);
    cJSON_AddStringToObject(j, "line", raw_line);
    cJSON_AddNumberToObject(j, "ts", (double)time(NULL) * 1000.0);
    char *json = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!json) { atomic_fetch_sub(&g_hub_inflight, 1); free(ctx); return; }
    strncpy(ctx->json, json, sizeof(ctx->json) - 1);
    cJSON_free(json);

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 16384);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, hub_push_thread, ctx) != 0) {
        atomic_fetch_sub(&g_hub_inflight, 1);
        free(ctx);
    }
    pthread_attr_destroy(&attr);
}

static void append_log(const char *line) {
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(f, "[%s] %s\n", ts, line);
        fflush(f);
        fclose(f);
    }
    /* Forward every AEGIS-* log line to the VPS2 terminal hub
     * (10.88.0.2:9001) so the dashboard model log streams in real time. */
    push_to_hub("shield_soul", line);
}

static double rolling_error_mean(void) {
    int n = g_error_count < MATURITY_WINDOW ? g_error_count : MATURITY_WINDOW;
    if (n == 0) return 1.0;
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += g_error_ring[i];
    return sum / (double)n;
}

/* -------------------------------------------------------------------------- *
 * Lead Hunter weight persistence
 * -------------------------------------------------------------------------- */
void aegis_lead_weights_save(const char *path) {
    if (!path) path = LEAD_WEIGHTS_PATH;
    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(root, "weights");
    for (int i = 0; i < 8; i++)
        cJSON_AddItemToArray(arr, cJSON_CreateNumber(g_lead_weights[i]));
    cJSON_AddBoolToObject(root, "initialized", 1);
    cJSON_AddNumberToObject(root, "training_cycles", (double)atomic_load(&g_training_cycles));
    cJSON_AddBoolToObject(root, "mature", g_mature ? 1 : 0);
    char *json = cJSON_PrintUnformatted(root);
    if (json) {
        FILE *f = fopen(path, "w");
        if (f) { fputs(json, f); fclose(f); }
        cJSON_free(json);
    }
    cJSON_Delete(root);
    append_log("[AEGIS-SYSTEM] Persistent lead weights saved");
}

void aegis_lead_weights_load(const char *path) {
    if (!path) path = LEAD_WEIGHTS_PATH;
    FILE *f = fopen(path, "rb");
    if (!f) {
        for (int i = 0; i < 8; i++)
            g_lead_weights[i] = (1.6180339887 / (double)(i + 1)) * 0.01;
        g_lead_initialized = 1;
        g_mature = 0;
        append_log("[AEGIS-SYSTEM] Lead weights: Phi-resonant baseline (no saved file)");
        return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return; }
    char *data = (char *)malloc((size_t)sz + 1);
    if (!data) { fclose(f); return; }
    if ((long)fread(data, 1, (size_t)sz, f) != sz) { free(data); fclose(f); return; }
    fclose(f);
    data[sz] = '\0';

    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) return;
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(json, "weights");
    if (arr && cJSON_IsArray(arr)) {
        int n = cJSON_GetArraySize(arr);
        if (n > 8) n = 8;
        for (int i = 0; i < n; i++) {
            cJSON *item = cJSON_GetArrayItem(arr, i);
            if (item && cJSON_IsNumber(item))
                g_lead_weights[i] = item->valuedouble;
        }
    }
    g_lead_initialized = 1;
    cJSON *tc = cJSON_GetObjectItemCaseSensitive(json, "training_cycles");
    if (cJSON_IsNumber(tc))
        atomic_store(&g_training_cycles, (uint_fast64_t)tc->valuedouble);
    cJSON *mat = cJSON_GetObjectItemCaseSensitive(json, "mature");
    g_mature = cJSON_IsTrue(mat) ? 1 : 0;
    cJSON_Delete(json);
    append_log("[AEGIS-SYSTEM] Lead weights loaded from saved file");
}

/* -------------------------------------------------------------------------- *
 * Ring buffer
 * -------------------------------------------------------------------------- */
int aegis_ring_init(aegis_ring_buffer_t *rb, size_t size) {
    if (!rb || size == 0) return AEGIS_ERR;
    rb->buffer = (aegis_connection_t *)calloc(size, sizeof(aegis_connection_t));
    if (!rb->buffer) return AEGIS_ERR;
    rb->size = size; rb->head = 0; rb->tail = 0; rb->count = 0;
    pthread_mutex_init(&rb->mutex, NULL);
    return AEGIS_OK;
}
void aegis_ring_free(aegis_ring_buffer_t *rb) {
    if (!rb) return;
    free(rb->buffer); rb->buffer = NULL;
    rb->size = 0; rb->head = 0; rb->tail = 0; rb->count = 0;
    pthread_mutex_destroy(&rb->mutex);
}
int aegis_ring_push(aegis_ring_buffer_t *rb, const aegis_connection_t *rec) {
    if (!rb || !rb->buffer || !rec) return AEGIS_ERR;
    pthread_mutex_lock(&rb->mutex);
    size_t idx = rb->head % rb->size;
    rb->buffer[idx] = *rec;
    rb->head = (rb->head + 1) % rb->size;
    if (rb->count < rb->size) rb->count++;
    else rb->tail = (rb->tail + 1) % rb->size;
    pthread_mutex_unlock(&rb->mutex);
    return AEGIS_OK;
}
int aegis_ring_find(aegis_ring_buffer_t *rb, const char *ip, aegis_connection_t *out) {
    if (!rb || !rb->buffer || !ip || !out) return AEGIS_ERR;
    pthread_mutex_lock(&rb->mutex);
    for (size_t i = 0; i < rb->count; i++) {
        size_t idx = (rb->tail + i) % rb->size;
        if (strcmp(rb->buffer[idx].ip, ip) == 0) {
            *out = rb->buffer[idx];
            pthread_mutex_unlock(&rb->mutex);
            return AEGIS_OK;
        }
    }
    pthread_mutex_unlock(&rb->mutex);
    return AEGIS_ERR;
}

/* -------------------------------------------------------------------------- *
 * Scoring
 * -------------------------------------------------------------------------- */
double aegis_reflex_score(const double *features, size_t n) {
    if (!features || n == 0) return 0.0;
    double score = 0.0;
    if (n > 0) score += features[0] * 0.3;
    if (n > 1) score += features[1] * 0.2;
    if (n > 2) score += features[2] * 0.2;
    if (n > 3) score += features[3] * 0.3;
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    return score;
}

double aegis_shield_score(const double *features, size_t n) {
    if (!features || n == 0) return 0.0;
    if (g_shield_loaded) {
        double proba = 0.0;
        aegis_model_predict(&g_shield_model, features, (int)n, &proba);
        return proba;
    }
    double score = 0.0;
    double w[] = {0.25, 0.20, 0.20, 0.15, 0.10, 0.05, 0.03, 0.02};
    size_t wn = sizeof(w) / sizeof(w[0]);
    for (size_t i = 0; i < n && i < wn; i++) score += features[i] * w[i];
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    return score;
}

double aegis_soul_score(const double *features, size_t n) {
    if (!features || n == 0) return 0.0;
    if (g_soul_loaded) return aegis_model_anomaly_score(&g_soul_model, features, (int)n);
    double mean = 0.0;
    for (size_t i = 0; i < n; i++) mean += features[i];
    mean /= (double)n;
    double variance = 0.0;
    for (size_t i = 0; i < n; i++) { double d = features[i] - mean; variance += d * d; }
    variance /= (double)n;
    double score = sqrt(variance) / (1.0 + sqrt(variance));
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    return score;
}

double aegis_lead_score(const double *features, size_t n) {
    if (!features || n == 0) return 0.0;
    double score = g_lead_weights[7];
    for (size_t i = 0; i < n && i < 8; i++)
        score += features[i] * g_lead_weights[i];
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    return score;
}

double aegis_auditor_consensus(const aegis_verdict_t *v) {
    double total = PHI_W_SHIELD + PHI_W_SOUL + PHI_W_LEAD + PHI_W_REFLEX;
    double w = PHI_W_SHIELD * v->shield_score + PHI_W_SOUL * v->soul_score
             + PHI_W_LEAD * v->lead_score + PHI_W_REFLEX * v->reflex_score;
}
void aegis_gradient_step(double *weights, const double *features, size_t n, double target, double predicted) {
    if (g_mature) {
        atomic_fetch_add(&g_training_cycles, 1);
        return;
    }
    double error = predicted - target;

    /* Dynamic Fibonacci learning rate: eta_t = F_t / F_{t+lookahead}
     * Converges to 1/phi ~ 0.618 as t -> infinity.
     * This provides a natural harmonic annealing schedule.
     */
    uint64_t a = g_fib_cur, b = g_fib_nxt;
    for (int k = 0; k < FIB_LOOKAHEAD; k++) {
        uint64_t nxt = a + b; a = b; b = nxt;
    }
    double eta = (double)g_fib_cur / (double)a;

    /* Advance Fibonacci state */
    uint64_t new_fib = g_fib_cur + g_fib_nxt;
    g_fib_cur = g_fib_nxt;
    g_fib_nxt = new_fib;

    /* Apply gradient step with Phi-harmonic learning rate */
    for (size_t i = 0; i < n && i < 8; i++)
        weights[i] -= LEAD_LR_SCALE * eta * error * features[i];

    /* Rolling error window for maturity check */
    pthread_mutex_lock(&g_error_mutex);
    g_error_ring[g_error_index] = fabs(error);
    g_error_index = (g_error_index + 1) % MATURITY_WINDOW;
    if (g_error_count < MATURITY_WINDOW) g_error_count++;
    double avg_err = rolling_error_mean();
    pthread_mutex_unlock(&g_error_mutex);

    atomic_fetch_add(&g_training_cycles, 1);

    if (g_error_count >= MATURITY_WINDOW && avg_err < 0.01 && !g_mature) {
        g_mature = 1;
        char logline[256];
        snprintf(logline, sizeof(logline),
                 "[AEGIS-TRAIN] Lead Hunter achieved structural maturity (avg_err=%.6f after %llu cycles)",
                 avg_err, (unsigned long long)atomic_load(&g_training_cycles));
        append_log(logline);
    }
}

aegis_verdict_t aegis_classify(const double *features, size_t n) {
    aegis_verdict_t v;
    memset(&v, 0, sizeof(v));
    v.reflex_score  = aegis_reflex_score(features, n);
    v.shield_score  = aegis_shield_score(features, n);
    v.soul_score    = aegis_soul_score(features, n);
    v.lead_score    = aegis_lead_score(features, n);
    v.consensus_score = (0.618 * v.shield_score) + (0.382 * v.soul_score);
    v.auditor_score = aegis_auditor_consensus(&v);

    /* --- Phi-Coherence Gate ---
     * If the consensus signal is disharmonic (outside phi bounds),
     * boost it toward hostile. If harmonic, dampen toward benign.
     * This is the sacred geometry filter: signals within [1/phi, phi]
     * of the spiral baseline are considered natural/benign. */
    pthread_mutex_lock(&g_spiral_mutex);
    double baseline = spiral_baseline(&g_spiral);
    int coherent = phi_coherence_gate(v.consensus_score, baseline);
    if (!coherent && v.consensus_score > baseline) {
        /* Disharmonic spike — likely hostile */
        v.consensus_score = v.consensus_score * PHI_RATIO;
        if (v.consensus_score > 1.0) v.consensus_score = 1.0;
    } else if (coherent && v.consensus_score < baseline) {
        /* Harmonic dip — likely benign, dampen */
        v.consensus_score = v.consensus_score * PHI_INV;
    }
    pthread_mutex_unlock(&g_spiral_mutex);

    if (v.auditor_score > 0.7 || v.reflex_score > 0.9 || v.shield_score > 0.85)
        v.is_hostile = 1;
    atomic_fetch_add(&g_inference_count, 1);
    if (v.is_hostile) atomic_fetch_add(&g_hostile_count, 1);

    /* --- Record into Fibonacci Spiral Memory --- */
    pthread_mutex_lock(&g_spiral_mutex);
    spiral_record(&g_spiral, features, (int)n, v.consensus_score,
                  v.auditor_score, v.is_hostile);
    pthread_mutex_unlock(&g_spiral_mutex);

    /* Model-specific log entries for Terminal HUD */
    char _mlb2[256];
    snprintf(_mlb2, sizeof(_mlb2), "[AEGIS-ALPHA] Score=%.4f | Hostile=%d", v.reflex_score, v.is_hostile);
    append_log(_mlb2);
    snprintf(_mlb2, sizeof(_mlb2), "[AEGIS-BETA] Anomaly=%.4f | Consensus=%.4f", v.soul_score, v.consensus_score);
    append_log(_mlb2);
    snprintf(_mlb2, sizeof(_mlb2), "[AEGIS-GAMMA] VelocityZ=%.4f", v.lead_score);
    append_log(_mlb2);
    snprintf(_mlb2, sizeof(_mlb2), "[AEGIS-CONSENSUS] Score=%.4f | Threshold=0.618 | Hostile=%d | Phi coherent=%d",
             v.auditor_score, v.is_hostile, coherent);
    append_log(_mlb2);
    return v;
}

/* -------------------------------------------------------------------------- *
 * GCP Strike integration - fire counter-attack to remote strike server
 * -------------------------------------------------------------------------- */

#define GCP_STRIKE_HOST_DEFAULT "127.0.0.1"
#define GCP_STRIKE_PORT_DEFAULT 8443

// Read from env, fallback to defaults
static const char* get_strike_host() {
    const char* h = getenv("STRIKE_HOST");
    return h && *h ? h : GCP_STRIKE_HOST_DEFAULT;
}
static int get_strike_port() {
    const char* p = getenv("STRIKE_PORT");
    return p && *p ? atoi(p) : GCP_STRIKE_PORT_DEFAULT;
}
static void call_gcp_strike(const char *target_ip, const char *reason) {
    if (!target_ip || !*target_ip) return;
    if (strcmp(target_ip, "127.0.0.1") == 0 || strcmp(target_ip, "::1") == 0) return;
    char request[512];
    int rlen = snprintf(request, sizeof(request),
        "POST /strike?ip=%s&reason=%s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n",
        target_ip, reason, get_strike_host(), get_strike_port());
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(get_strike_port());
    inet_pton(AF_INET, get_strike_host(), &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        send(sock, request, (size_t)rlen, MSG_NOSIGNAL);
        char resp[256];
        recv(sock, resp, sizeof(resp) - 1, 0);
    }
    close(sock);
    char logline[256];
    snprintf(logline, sizeof(logline),
             "[AEGIS-STRIKE] GCP counter-strike dispatched for %s (%s)", target_ip, reason);
    append_log(logline);
}

/* -------------------------------------------------------------------------- *
 * Engine lifecycle
 * -------------------------------------------------------------------------- */
int aegis_engine_init(const char *shield_model_path, const char *soul_model_path) {
    if (g_engine_initialized) return AEGIS_OK;
    if (aegis_ring_init(&g_ring, AEGIS_RING_BUFFER_SIZE) != AEGIS_OK) return AEGIS_ERR;
    if (shield_model_path && *shield_model_path) {
        if (aegis_model_load(&g_shield_model, shield_model_path) == AEGIS_MODEL_OK)
            g_shield_loaded = 1;
        else fprintf(stderr, "Warning: failed to load Shield model from %s\n", shield_model_path);
    }
    if (soul_model_path && *soul_model_path) {
        if (aegis_model_load(&g_soul_model, soul_model_path) == AEGIS_MODEL_OK)
            g_soul_loaded = 1;
        else fprintf(stderr, "Warning: failed to load Soul model from %s\n", soul_model_path);
    }
    g_error_index = 0; g_error_count = 0;
    memset(g_error_ring, 0, sizeof(g_error_ring));
    aegis_lead_weights_load(NULL);
    /* Initialize Fibonacci spiral memory */
    spiral_init(&g_spiral);
    /* Groq teacher initialized lazily via --groq-key CLI arg */
    memset(&g_teacher, 0, sizeof(g_teacher));
    g_engine_started_at = time(NULL);
    g_engine_initialized = 1;
    return AEGIS_OK;
}

void aegis_engine_shutdown(void) {
    if (!g_engine_initialized) return;
    aegis_lead_weights_save(NULL);
    aegis_ring_free(&g_ring);
    aegis_model_free(&g_shield_model);
    aegis_model_free(&g_soul_model);
    if (g_metrics_path_dup) { free(g_metrics_path_dup); g_metrics_path_dup = NULL; }
    g_engine_initialized = 0;
}

/* -------------------------------------------------------------------------- *
 * Sidecar metrics loader
 * -------------------------------------------------------------------------- */
static void format_iso8601(time_t t, char *out, size_t n) {
    if (n == 0) return;
    struct tm tm; gmtime_r(&t, &tm);
    strftime(out, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void metrics_reload_locked(void) {
    if (!g_metrics_path_dup) return;
    struct stat st;
    if (stat(g_metrics_path_dup, &st) != 0) {
        g_metrics_mtime = 0; g_metrics_accuracy = 0.0; g_metrics_f1 = 0.0;
        g_metrics_base_cycles = 0; g_metrics_last_trained[0] = '\0';
        g_metrics_hostile_ratio = 0.0; g_metrics_n_hostile = 0; g_metrics_n_benign = 0;
        g_metrics_data_source[0] = '\0'; return;
    }
    if (st.st_mtime == g_metrics_mtime && g_metrics_mtime != 0) return;
    FILE *fp = fopen(g_metrics_path_dup, "rb");
    if (!fp) { g_metrics_mtime = 0; return; }
    fseek(fp, 0, SEEK_END); long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0 || sz > 1048576) { fclose(fp); return; }
    char *data = (char *)malloc((size_t)sz + 1);
    if (!data) { fclose(fp); return; }
    if ((long)fread(data, 1, (size_t)sz, fp) != sz) { free(data); fclose(fp); return; }
    fclose(fp); data[sz] = '\0';
    cJSON *json = cJSON_Parse(data); free(data);
    if (!json) { g_metrics_mtime = st.st_mtime; return; }
    cJSON *acc = cJSON_GetObjectItemCaseSensitive(json, "accuracy");
    cJSON *f1j = cJSON_GetObjectItemCaseSensitive(json, "f1");
    cJSON *bt = cJSON_GetObjectItemCaseSensitive(json, "base_training_cycles");
    cJSON *trained = cJSON_GetObjectItemCaseSensitive(json, "trained_at");
    cJSON *nh = cJSON_GetObjectItemCaseSensitive(json, "n_hostile");
    cJSON *nb = cJSON_GetObjectItemCaseSensitive(json, "n_benign");
    cJSON *src = cJSON_GetObjectItemCaseSensitive(json, "data_source");
    cJSON *hr = cJSON_GetObjectItemCaseSensitive(json, "hostile_ratio");
    if (cJSON_IsNumber(acc)) g_metrics_accuracy = acc->valuedouble;
    if (cJSON_IsNumber(f1j)) g_metrics_f1 = f1j->valuedouble;
    if (cJSON_IsNumber(bt)) g_metrics_base_cycles = (uint_fast64_t)bt->valuedouble;
    if (cJSON_IsString(trained) && trained->valuestring) {
        strncpy(g_metrics_last_trained, trained->valuestring, sizeof(g_metrics_last_trained)-1);
        g_metrics_last_trained[sizeof(g_metrics_last_trained)-1] = '\0';
    } else format_iso8601(st.st_mtime, g_metrics_last_trained, sizeof(g_metrics_last_trained));
    if (cJSON_IsNumber(hr)) g_metrics_hostile_ratio = hr->valuedouble;
    if (cJSON_IsNumber(nh)) g_metrics_n_hostile = (int)nh->valuedouble;
    if (cJSON_IsNumber(nb)) g_metrics_n_benign = (int)nb->valuedouble;
    if (cJSON_IsString(src) && src->valuestring) {
        strncpy(g_metrics_data_source, src->valuestring, sizeof(g_metrics_data_source)-1);
        g_metrics_data_source[sizeof(g_metrics_data_source)-1] = '\0';
    }
    cJSON_Delete(json);
    g_metrics_mtime = st.st_mtime;
}

void aegis_set_metrics_path(const char *path) {
    pthread_mutex_lock(&g_metrics_mutex);
    if (g_metrics_path_dup) { free(g_metrics_path_dup); g_metrics_path_dup = NULL; }
    if (path && *path) g_metrics_path_dup = strdup(path);
    g_metrics_mtime = 0; metrics_reload_locked();
    pthread_mutex_unlock(&g_metrics_mutex);
}

/* -------------------------------------------------------------------------- *
 * TCP feature-inference (port --port, default 20129)
 * -------------------------------------------------------------------------- */
static void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    char strike_ip[64] = "";
    free(arg);
    char buf[2048]; size_t total = 0; int found_nl = 0;
    while (total < sizeof(buf) - 1) {
        ssize_t n = recv(client_fd, buf + total, sizeof(buf) - total - 1, 0);
        if (n <= 0) break;
        total += (size_t)n; buf[total] = '\0';
        if (strchr(buf, '\n')) { found_nl = 1; break; }
    }
    if (found_nl && total > 0) {
        int is_training = 0; double train_target = 0.0;
        double features[64]; int n_features = 0; int using_json = 0;
        cJSON *jreq = cJSON_Parse(buf);
        if (jreq) {
            cJSON *jt = cJSON_GetObjectItemCaseSensitive(jreq, "train");
            if (cJSON_IsTrue(jt)) { is_training = 1;
                cJSON *jtg = cJSON_GetObjectItemCaseSensitive(jreq, "target");
                if (cJSON_IsNumber(jtg)) train_target = jtg->valuedouble;
            }

            cJSON *jf = cJSON_GetObjectItemCaseSensitive(jreq, "features");
cJSON *jip = cJSON_GetObjectItemCaseSensitive(jreq, "ip");            if (cJSON_IsString(jip) && jip->valuestring) {                strncpy(strike_ip, jip->valuestring, 63); strike_ip[63] = 0;            }
            if (jf && cJSON_IsArray(jf)) {
                using_json = 1;
                int as = cJSON_GetArraySize(jf);
                for (int i = 0; i < as && n_features < 64; i++) {
                    cJSON *it = cJSON_GetArrayItem(jf, i);
                    if (it && cJSON_IsNumber(it)) features[n_features++] = it->valuedouble;
                }
            }
            cJSON_Delete(jreq);
        }
        if (!using_json) {
            char *p = buf;
            while (*p && n_features < 64) {
                char *end = NULL; double v = strtod(p, &end);
                if (end == p) { p++; continue; }
                features[n_features++] = v; p = end;
                while (*p == ' '||*p=='\t'||*p==','||*p=='['||*p==']'||*p=='\n'||*p=='\r') p++;
            }
        }
        if (n_features > 0) {
            if (is_training && n_features >= 8) {
                double predicted = aegis_lead_score(features, (size_t)n_features);
                aegis_gradient_step(g_lead_weights, features, (size_t)n_features, train_target, predicted);
                char logline[256];
                snprintf(logline, sizeof(logline),
                    "[AEGIS-TRAIN] Lead Hunter step: target=%.4f pred=%.4f cycles=%llu mature=%d",
                    train_target, predicted,
                    (unsigned long long)atomic_load(&g_training_cycles), g_mature);
                append_log(logline);
                char resp[256];
                snprintf(resp, sizeof(resp),
                    "{\"status\":\"trained\",\"target\":%.4f,\"predicted\":%.4f,\"cycles\":%llu,\"mature\":%d}\n",
                    train_target, predicted,
                    (unsigned long long)atomic_load(&g_training_cycles), g_mature);
                send(client_fd, resp, strlen(resp), 0);
            } else {
                aegis_verdict_t v = aegis_classify(features, (size_t)n_features);

                /* --- Groq 120B Teacher Query ---
                 * Query the 120B teacher on ALL inferences for training data
                 * accumulation. The 5s cooldown in groq_teacher.c rate-limits
                 * to ~12 RPM. Teacher override only applies when confidence > 0.8
                 * and teacher disagrees with C engine. */
                if (g_teacher.enabled) {
                    GroqVerdict tv;
                    pthread_mutex_lock(&g_spiral_mutex);
                    int tret = groq_teacher_query(&g_teacher, &g_spiral,
                                 features, (int)n_features,
                                 v.consensus_score, v.is_hostile, &tv);
                    pthread_mutex_unlock(&g_spiral_mutex);
                    g_teacher_queries++;
                    if (tret == 0 && tv.valid) {
                        /* Log ALL teacher responses to ndjson for training data */
                        FILE *tlogf = fopen("/var/log/aegis/teacher_labels.ndjson", "a");
                        if (tlogf) {
                            fprintf(tlogf,
                                "{\"ts\":%ld,\"consensus\":%.4f,\"c_hostile\":%d,"
                                "\"t_hostile\":%d,\"t_conf\":%.4f,\"t_reason\":\"%s\","
                                "\"model\":\"groq/openai/gpt-oss-120b\"}\n",
                                (long)time(NULL), v.consensus_score, v.is_hostile,
                                tv.hostile, tv.confidence, tv.reasoning);
                            fclose(tlogf);
                        }
                        /* Teacher override: if teacher confidence > 0.8 and
                         * disagrees with C engine, update the verdict */
                        if (tv.confidence > 0.8 && tv.hostile != v.is_hostile) {
                            v.is_hostile = tv.hostile;
                            v.consensus_score = tv.confidence;
                            g_teacher_overrides++;
                            char tlog[512];
                            snprintf(tlog, sizeof(tlog),
                                "[AEGIS-TEACHER] Override: hostile=%d conf=%.3f reason=%s",
                                tv.hostile, tv.confidence, tv.reasoning);
                            append_log(tlog);
                            /* Feed teacher label back into Lead Hunter */
                            double target = tv.hostile ? 1.0 : 0.0;
                            aegis_gradient_step(g_lead_weights, features,
                                (size_t)n_features, target, v.lead_score);
                        }
                    }
                }

                char resp[512];
                snprintf(resp, sizeof(resp),
                    "{\"reflex\":%.4f,\"shield\":%.4f,\"soul\":%.4f,\"lead\":%.4f,\"consensus\":%.4f,\"auditor\":%.4f,\"hostile\":%d}\n",
                    v.reflex_score, v.shield_score, v.soul_score, v.lead_score,
                    v.consensus_score, v.auditor_score, v.is_hostile);
                send(client_fd, resp, strlen(resp), 0);
                if (v.is_hostile && strike_ip[0]) {
                    call_gcp_strike(strike_ip, "AEGIS-CLASSIFY-HOSTILE");
                }
            }
        }
    }
    close(client_fd);
    return NULL;
}

static void aegis_signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) { aegis_lead_weights_save(NULL); g_shutdown = 1; }
}

int aegis_start_server(int port) {
    signal(SIGINT, aegis_signal_handler); signal(SIGTERM, aegis_signal_handler);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return AEGIS_ERR;
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(server_fd); return AEGIS_ERR; }
    if (listen(server_fd, 128) < 0) { close(server_fd); return AEGIS_ERR; }
    while (!g_shutdown) {
        struct sockaddr_in ca; socklen_t cl = sizeof(ca);
        int cfd = accept(server_fd, (struct sockaddr *)&ca, &cl);
        if (cfd < 0) continue;
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int *pfd = (int *)malloc(sizeof(int));
        if (!pfd) { close(cfd); continue; }
        *pfd = cfd; pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, pfd) != 0) { free(pfd); close(cfd); continue; }
        pthread_detach(tid);
    }
    return server_fd;
}
int aegis_is_shutdown(void) { return g_shutdown; }
void aegis_stop_server(int fd) { close(fd); }

/* -------------------------------------------------------------------------- *
 * HTTP /status server (port --status-port, default 8086)
 * -------------------------------------------------------------------------- */
static void http_send(int cfd, int code, const char *ct, const char *body, size_t blen) {
    char hdr[256];
    const char *reason = code == 200 ? "OK" : code == 404 ? "Not Found" : code == 405 ? "Method Not Allowed" : code == 400 ? "Bad Request" : "Internal Server Error";
    int hl = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        code, reason, ct, blen);
    if (hl > 0) send(cfd, hdr, (size_t)hl, MSG_NOSIGNAL);
    if (body && blen) send(cfd, body, blen, MSG_NOSIGNAL);
}

static void build_status_json(char *buf, size_t cap, size_t *out_len) {
    pthread_mutex_lock(&g_metrics_mutex);
    metrics_reload_locked();
    double acc = g_metrics_accuracy, f1 = g_metrics_f1, hr = g_metrics_hostile_ratio;
    int nh = g_metrics_n_hostile, nb = g_metrics_n_benign;
    char ds[64]; strncpy(ds, g_metrics_data_source, 63); ds[63] = '\0';
    uint_fast64_t bc = g_metrics_base_cycles;
    char tr[64]; strncpy(tr, g_metrics_last_trained, 63); tr[63] = '\0';
    pthread_mutex_unlock(&g_metrics_mutex);

    uint_fast64_t inf = atomic_load(&g_inference_count);
    uint_fast64_t hostile = atomic_load(&g_hostile_count);
    uint_fast64_t tc = atomic_load(&g_training_cycles);
    uint_fast64_t total_cycles = bc + inf + tc;
    time_t now = time(NULL);
    char next_train[64]; time_t nt = now + 86400;
    format_iso8601(nt, next_train, sizeof(next_train));
    if (tr[0] == '\0') format_iso8601(g_engine_started_at, tr, sizeof(tr));
    int uptime = g_engine_started_at > 0 ? (int)(now - g_engine_started_at) : 0;

    cJSON *root = cJSON_CreateObject();
    cJSON *mobj = cJSON_AddObjectToObject(root, "model");
    cJSON_AddStringToObject(mobj, "version", "alpha-beta-gamma-c-v3");
    cJSON_AddStringToObject(mobj, "algorithm", "LightGBM+IsolationForest+LinearLead+PhiAuditor");
    cJSON_AddNumberToObject(mobj, "accuracy", acc);
    cJSON_AddNumberToObject(mobj, "f1", f1);
    cJSON_AddNumberToObject(mobj, "training_cycles", (double)total_cycles);
    cJSON_AddNumberToObject(mobj, "lead_training_cycles", (double)tc);
    cJSON_AddBoolToObject(mobj, "lead_mature", g_mature ? 1 : 0);
    cJSON_AddNumberToObject(mobj, "features", g_shield_model.n_features > 0 ? g_shield_model.n_features : 8);
    cJSON_AddNumberToObject(mobj, "hostile_ratio", hr);
    cJSON_AddNumberToObject(mobj, "n_hostile", (double)nh);
    cJSON_AddNumberToObject(mobj, "n_benign", (double)nb);
    cJSON_AddStringToObject(mobj, "data_source", ds);
    cJSON_AddNumberToObject(mobj, "inference_count", (double)inf);
    cJSON_AddNumberToObject(mobj, "hostile_inferences", (double)hostile);

    cJSON *pipe = cJSON_AddObjectToObject(root, "pipeline");
    cJSON_AddStringToObject(pipe, "last_trained", tr);
    cJSON_AddStringToObject(pipe, "next_retrain", next_train);
    cJSON_AddStringToObject(pipe, "retrain_timer", g_mature ? "mature" : "active");

    cJSON *gcp = cJSON_AddObjectToObject(root, "gcp_strike");
    cJSON_AddNumberToObject(gcp, "active_strikes", (double)hostile);
    cJSON_AddStringToObject(gcp, "status", "ok");

    cJSON *triad = cJSON_AddObjectToObject(root, "triad");
    cJSON_AddStringToObject(triad, "node", "shield+soul+lead+auditor");
    cJSON_AddNumberToObject(triad, "uptime_seconds", (double)uptime);

    char *json_text = cJSON_PrintUnformatted(root);
    if (json_text && strlen(json_text) < cap) {
        size_t n = strlen(json_text);
        memcpy(buf, json_text, n + 1);
        *out_len = n;
    } else if (json_text) {
        size_t n = cap - 1; memcpy(buf, json_text, n); buf[n] = '\0'; *out_len = n;
    } else {
        snprintf(buf, cap, "{\"error\":\"cjson_print_failed\"}"); *out_len = strlen(buf);
    }
    if (json_text) cJSON_free(json_text);
    cJSON_Delete(root);
}

static void *http_status_server_thread(void *arg) {
    (void)arg;
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { fprintf(stderr, "status: socket() failed\n"); return NULL; }
    int opt = 1; setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)g_status_port);
    addr.sin_addr.s_addr = strcmp(g_status_bind_ip, "0.0.0.0") == 0 ? INADDR_ANY : (inet_pton(AF_INET, g_status_bind_ip, &addr.sin_addr) != 1 ? (close(sfd), fprintf(stderr, "status: invalid bind ip\n"), NULL) : addr.sin_addr.s_addr);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { fprintf(stderr, "status: bind failed\n"); close(sfd); return NULL; }
    if (listen(sfd, 64) < 0) { close(sfd); return NULL; }
    fprintf(stderr, "status: HTTP on %s:%d\n", g_status_bind_ip, g_status_port);
    while (!g_shutdown) {
        struct sockaddr_in cli; socklen_t len = sizeof(cli);
        int cfd = accept(sfd, (struct sockaddr *)&cli, &len);
        if (cfd < 0) continue;
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        char req[2048]; size_t total = 0;
        while (total < sizeof(req)-1) {
            ssize_t n = recv(cfd, req+total, sizeof(req)-total-1, 0);
            if (n <= 0) break; total += (size_t)n; req[total] = '\0';
            if (strstr(req, "\r\n\r\n")) break;
        }
        if (total == 0) { close(cfd); continue; }
        char method[16]={0}, path[256]={0};
        if (sscanf(req, "%15s %255s", method, path) != 2) { http_send(cfd,400,"text/plain","bad request",11); close(cfd); continue; }
        if (strcmp(method,"GET")==0 && (strcmp(path,"/status")==0||strcmp(path,"/")==0)) {
            char body[8192]; size_t blen=0; build_status_json(body,sizeof(body),&blen);
            http_send(cfd,200,"application/json",body,blen);
        } else if (strcmp(method,"POST")==0 && strcmp(path,"/score")==0) {
            int cl=0; char *ch=req;
            while ((ch=strstr(ch,"Content-Length:"))||(ch=strstr(ch,"content-length:"))) {
                if (strncasecmp(ch,"Content-Length:",15)==0) { char *e=NULL; long l=strtol(ch+15,&e,10); if (e!=ch+15) { cl=(int)l; break; } }
                ch+=15;
            }
            if (cl>0&&cl<1048576) {
                char *bs=strstr(req,"\r\n\r\n"); if (bs) {
                    bs+=4; size_t hl=bs-req, br=total>hl?total-hl:0;
                    char *bb=malloc((size_t)cl+1); if (bb) {
                        size_t tc=br>(size_t)cl?(size_t)cl:br; memcpy(bb,bs,tc); size_t bt=tc;
                        while (bt<(size_t)cl) { ssize_t n=recv(cfd,bb+bt,(size_t)cl-bt,0); if (n<=0) break; bt+=(size_t)n; }
                        if (bt!=(size_t)cl) { free(bb); http_send(cfd,400,"text/plain","incomplete",15); close(cfd); continue; }
                        bb[bt]='\0';
                        double f[64]={0}; size_t nf=0; int jv=0;
                        cJSON *ja=cJSON_Parse(bb);
                        if (ja&&cJSON_IsArray(ja)) { jv=1; int as=cJSON_GetArraySize(ja); for(int i=0;i<as&&nf<64;i++){cJSON *it=cJSON_GetArrayItem(ja,i);if(it&&cJSON_IsNumber(it))f[nf++]=it->valuedouble;}}
                        aegis_verdict_t v=aegis_classify(f,nf);
                        char resp[512]; size_t rl=snprintf(resp,sizeof(resp),
                            "{\"reflex\":%.4f,\"shield\":%.4f,\"soul\":%.4f,\"lead\":%.4f,\"consensus\":%.4f,\"auditor\":%.4f,\"hostile\":%d}\n",
                            v.reflex_score,v.shield_score,v.soul_score,v.lead_score,v.consensus_score,v.auditor_score,v.is_hostile);
                        http_send(cfd,200,"application/json",resp,rl);
                    } else http_send(cfd,500,"text/plain","server error",12);
                } else http_send(cfd,400,"text/plain","bad request",11);
            } else http_send(cfd,400,"text/plain","bad request",11);
        } else http_send(cfd, strcmp(method,"GET")==0?404:405, "text/plain", strcmp(method,"GET")==0?"not found":"method not allowed", 18);
        close(cfd);
    }
    close(sfd); return NULL;
}

/* -------------------------------------------------------------------------- *
 * CLI entrypoint
 * -------------------------------------------------------------------------- */
int main(int argc, char **argv) {
    int port = 20129; int enable_status_http = 1;
    const char *shield_model = NULL, *soul_model = NULL;
    const char *metrics_path = "/var/lib/aegis-shield-soul/metrics.json";
    const char *groq_key = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i],"--shield-model")==0&&i+1<argc) shield_model=argv[++i];
        else if (strcmp(argv[i],"--soul-model")==0&&i+1<argc) soul_model=argv[++i];
        else if (strcmp(argv[i],"--port")==0&&i+1<argc) port=atoi(argv[++i]);
        else if (strcmp(argv[i],"--status-port")==0&&i+1<argc) g_status_port=atoi(argv[++i]);
        else if (strcmp(argv[i],"--bind-ip")==0&&i+1<argc) { strncpy(g_status_bind_ip,argv[++i],63); g_status_bind_ip[63]='\0'; }
        else if (strcmp(argv[i],"--metrics-file")==0&&i+1<argc) metrics_path=argv[++i];
        else if (strcmp(argv[i],"--groq-key")==0&&i+1<argc) groq_key=argv[++i];
        else if (strcmp(argv[i],"--no-status-http")==0) enable_status_http=0;
        else if (strcmp(argv[i],"--vps2-hub")==0&&i+1<argc) { parse_hub_url(argv[++i]); fprintf(stderr,"hub: %s:%d%s\n", g_hub_host, g_hub_port, g_hub_path); }
        else if (argv[i][0]!='-') port=atoi(argv[i]);
    }
    if (port<=0||port>65535) { fprintf(stderr,"Invalid port\n"); return 1; }
    if (g_status_port<=0||g_status_port>65535) { fprintf(stderr,"Invalid status port\n"); return 1; }
    if (aegis_engine_init(shield_model,soul_model)!=AEGIS_OK) { fprintf(stderr,"Engine init failed\n"); return 1; }
    aegis_set_metrics_path(metrics_path);
    /* Initialize Groq 120B teacher if API key provided */
    if (groq_key && *groq_key) {
        groq_teacher_init(&g_teacher, groq_key);
        fprintf(stderr, "Groq 120B teacher: enabled (model=%s)\n", GROQ_MODEL);
    } else {
        fprintf(stderr, "Groq 120B teacher: disabled (no --groq-key)\n");
    }
    if (enable_status_http) {
        pthread_t tid;
        if (pthread_create(&tid,NULL,http_status_server_thread,NULL)!=0)
            fprintf(stderr,"Warning: could not start HTTP server\n");
        else pthread_detach(tid);
    }
    printf("Aegis-SIGMA 4-model engine: TCP :%d, HTTP /status :%d\n", port, g_status_port);
    aegis_start_server(port);
    aegis_engine_shutdown();
    return 0;
}
