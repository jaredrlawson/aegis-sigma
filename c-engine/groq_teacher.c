/*
 * Aegis-SIGMA Groq 120B Teacher Bridge
 *
 * Queries the Go Shield's /api/groq-teacher proxy endpoint with
 * Fibonacci-windowed context from the spiral memory. The Go shield
 * forwards to Groq's 120B LLM API and returns an authoritative
 * benign/hostile label. The teacher's verdict feeds back into
 * Lead Hunter weights via gradient descent.
 *
 * Architecture: C engine → Go shield proxy (localhost:3000) → Groq API
 * This avoids HTTPS dependencies in the C binary.
 */

#include "groq_teacher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

/* Go shield proxy endpoint (localhost:3000) */
#define SHIELD_PROXY_HOST "127.0.0.1"
#define SHIELD_PROXY_PORT 3000
#define SHIELD_PROXY_PATH "/api/groq-teacher"

void groq_teacher_init(GroqTeacher *gt, const char *api_key) {
    if (!gt) return;
    memset(gt, 0, sizeof(GroqTeacher));
    if (api_key && *api_key) {
        strncpy(gt->api_key, api_key, sizeof(gt->api_key) - 1);
        gt->enabled = 1;
    }
    gt->cooldown_sec = 5;
    gt->last_call = 0;
}

/* Build Fibonacci-windowed context from spiral memory.
 * Uses tier 0 (1 sample), tier 2 (2 samples), tier 3 (3 samples)
 * = 6 most representative historical classifications. */
static void build_fibonacci_context(const SpiralMemory *sm, cJSON *obj) {
    if (!sm || !obj) return;

    cJSON *history = cJSON_AddArrayToObject(obj, "spiral_history");

    /* Fibonacci tiers: 0 (cap=1), 2 (cap=2), 3 (cap=3) */
    int tiers[] = {0, 2, 3};
    int ntiers = 3;

    for (int t = 0; t < ntiers; t++) {
        int tier = tiers[t];
        int count = sm->tier_count[tier];
        if (count == 0) continue;

        const SpiralNode *node = &sm->tiers[tier][count - 1];
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddNumberToObject(entry, "tier", tier);
        cJSON_AddNumberToObject(entry, "consensus", node->consensus);
        cJSON_AddNumberToObject(entry, "auditor", node->auditor_score);
        cJSON_AddNumberToObject(entry, "hostile", node->hostile);
        cJSON_AddNumberToObject(entry, "resonance", node->resonance);
        cJSON_AddItemToArray(history, entry);
    }

    cJSON_AddNumberToObject(obj, "phi_baseline", sm->phi_baseline);
    cJSON_AddNumberToObject(obj, "total_samples", sm->total_samples);
}

/* Parse proxy response for teacher verdict. */
static int parse_teacher_response(const char *json_str, GroqVerdict *out) {
    if (!json_str || !out) return -1;
    memset(out, 0, sizeof(GroqVerdict));

    cJSON *root = cJSON_Parse(json_str);
    if (!root) return -1;

    cJSON *verdict = cJSON_GetObjectItemCaseSensitive(root, "verdict");
    cJSON *confidence = cJSON_GetObjectItemCaseSensitive(root, "confidence");
    cJSON *reasoning = cJSON_GetObjectItemCaseSensitive(root, "reasoning");

    if (cJSON_IsString(verdict)) {
        out->hostile = (strcmp(verdict->valuestring, "HOSTILE") == 0) ? 1 : 0;
    }
    if (cJSON_IsNumber(confidence)) {
        out->confidence = confidence->valuedouble;
        if (out->confidence < 0.0) out->confidence = 0.0;
        if (out->confidence > 1.0) out->confidence = 1.0;
    } else {
        out->confidence = 0.5;
    }
    if (cJSON_IsString(reasoning) && reasoning->valuestring) {
        strncpy(out->reasoning, reasoning->valuestring, 511);
        out->reasoning[511] = '\0';
    }

    out->valid = 1;
    cJSON_Delete(root);
    return 0;
}

int groq_teacher_query(GroqTeacher *gt, const SpiralMemory *sm,
                       const double *features, int n_features,
                       double c_engine_consensus, int c_engine_hostile,
                       GroqVerdict *out) {
    if (!gt || !out || !gt->enabled || !gt->api_key[0]) return -1;
    if (!features || n_features == 0) return -1;

    /* Rate limiting */
    time_t now = time(NULL);
    if (now - gt->last_call < gt->cooldown_sec) return -1;
    gt->last_call = now;

    /* Build JSON request to Go shield proxy */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "api_key", gt->api_key);
    cJSON_AddNumberToObject(root, "c_engine_consensus", c_engine_consensus);
    cJSON_AddNumberToObject(root, "c_engine_hostile", c_engine_hostile);

    /* Add features array */
    cJSON *feats = cJSON_AddArrayToObject(root, "features");
    for (int i = 0; i < n_features && i < 30; i++) {
        cJSON_AddItemToArray(feats, cJSON_CreateNumber(features[i]));
    }

    /* Add Fibonacci spiral context */
    build_fibonacci_context(sm, root);

    char *json_body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_body) return -1;

    /* HTTP POST to Go shield proxy */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { cJSON_free(json_body); return -1; }

    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SHIELD_PROXY_PORT);
    inet_pton(AF_INET, SHIELD_PROXY_HOST, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        cJSON_free(json_body);
        gt->total_errors++;
        return -1;
    }

    /* Build HTTP request */
    char request[GROQ_BUFFER_SIZE];
    int rlen = snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        SHIELD_PROXY_PATH, SHIELD_PROXY_HOST, SHIELD_PROXY_PORT,
        strlen(json_body), json_body);

    send(sock, request, (size_t)rlen, MSG_NOSIGNAL);

    /* Read response */
    char response[GROQ_BUFFER_SIZE];
    size_t total = 0;
    while (total < sizeof(response) - 1) {
        ssize_t n = recv(sock, response + total, sizeof(response) - total - 1, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    response[total] = '\0';
    close(sock);
    cJSON_free(json_body);

    if (total == 0) { gt->total_errors++; return -1; }

    /* Skip HTTP headers, find JSON body */
    char *body = strstr(response, "\r\n\r\n");
    if (!body) { gt->total_errors++; return -1; }
    body += 4;

    /* Parse response */
    if (parse_teacher_response(body, out) == 0) {
        gt->total_calls++;
        return 0;
    }

    gt->total_errors++;
    return -1;
}
