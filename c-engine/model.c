/*
 * Aegis-SIGMA Shield/Soul — JSON tree model inference
 *
 * Loads tree-based ML models (RandomForest / IsolationForest) exported from
 * Python as JSON and runs inference in pure C. JSON parsing is handled by
 * the cJSON library for robustness and security.
 */

#include "model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

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

#ifdef AEGIS_USE_LIGHTGBM
#include <lightgbm/c_api.h>
#endif

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */
static int read_file(const char *path, char **out_data, size_t *out_len) {
    if (!path || !out_data || !out_len) return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size < 0) {
        fclose(fp);
        return -1;
    }

    char *data = (char *)malloc((size_t)size + 1);
    if (!data) {
        fclose(fp);
        return -1;
    }

    if ((long)fread(data, 1, (size_t)size, fp) != size) {
        free(data);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    data[size] = '\0';

    *out_data = data;
    *out_len = (size_t)size;
    return 0;
}

static int parse_type(const char *s, aegis_tree_type_t *out) {
    if (!s || !out) return AEGIS_MODEL_ERR;
    if (strcmp(s, "isolation_forest") == 0) *out = AEGIS_TREE_ISOLATION;
    else if (strcmp(s, "regression") == 0) *out = AEGIS_TREE_REGRESSION;
    else *out = AEGIS_TREE_CLASSIFICATION;
    return AEGIS_MODEL_OK;
}

static int parse_tree(aegis_tree_t *tree, const cJSON *tree_obj) {
    if (!tree || !cJSON_IsObject(tree_obj)) return AEGIS_MODEL_ERR;

    tree->n_nodes = 0;
    memset(tree->nodes, 0, sizeof(tree->nodes));

    const cJSON *nodes = cJSON_GetObjectItemCaseSensitive(tree_obj, "nodes");
    if (!cJSON_IsArray(nodes)) return AEGIS_MODEL_ERR;

    int n_nodes = cJSON_GetArraySize(nodes);
    if (n_nodes < 1 || n_nodes > AEGIS_MAX_NODES) return AEGIS_MODEL_ERR;

    for (int i = 0; i < n_nodes; i++) {
        cJSON *node_obj = cJSON_GetArrayItem(nodes, i);
        if (!cJSON_IsObject(node_obj)) return AEGIS_MODEL_ERR;

        if (tree->n_nodes >= AEGIS_MAX_NODES) return AEGIS_MODEL_ERR;
        aegis_tree_node_t *node = &tree->nodes[tree->n_nodes++];
        node->feature = -1;
        node->threshold = 0.0;
        node->left = -1;
        node->right = -1;
        node->is_leaf = 0;
        memset(node->value, 0, sizeof(node->value));

        cJSON *feature = cJSON_GetObjectItemCaseSensitive(node_obj, "feature");
        cJSON *threshold = cJSON_GetObjectItemCaseSensitive(node_obj, "threshold");
        cJSON *left = cJSON_GetObjectItemCaseSensitive(node_obj, "left");
        cJSON *right = cJSON_GetObjectItemCaseSensitive(node_obj, "right");
        cJSON *is_leaf_obj = cJSON_GetObjectItemCaseSensitive(node_obj, "is_leaf");
        cJSON *value = cJSON_GetObjectItemCaseSensitive(node_obj, "value");

        if (cJSON_IsNumber(feature)) node->feature = (int)feature->valuedouble;
        if (cJSON_IsNumber(threshold)) node->threshold = threshold->valuedouble;
        if (cJSON_IsNumber(left)) node->left = (int)left->valuedouble;
        if (cJSON_IsNumber(right)) node->right = (int)right->valuedouble;
        if (cJSON_IsNumber(is_leaf_obj)) node->is_leaf = (int)is_leaf_obj->valuedouble;

        if (cJSON_IsArray(value)) {
            int n_values = cJSON_GetArraySize(value);
            for (int j = 0; j < n_values && j < AEGIS_MAX_CLASSES; j++) {
                cJSON *v = cJSON_GetArrayItem(value, j);
                if (cJSON_IsNumber(v)) {
                    node->value[j] = v->valuedouble;
                }
            }
        }
    }

    return AEGIS_MODEL_OK;
}

/* --------------------------------------------------------------------------
 * Model loading
 * -------------------------------------------------------------------------- */
int aegis_model_load(aegis_model_t *model, const char *path) {
    if (!model || !path) return AEGIS_MODEL_ERR;

    memset(model, 0, sizeof(*model));
    model->n_classes = 2;
    model->n_features = 16;
    model->n_samples = 256;
    model->type = AEGIS_TREE_CLASSIFICATION;
    if (path) {
        const char *base = strrchr(path, '/');
        if (!base) base = strrchr(path, '\\');
        if (base) base++;
        else base = path;
        strncpy(model->name, base, sizeof(model->name) - 1);
        model->name[sizeof(model->name) - 1] = '\0';
    }

    /* LightGBM native model files are plain text ending in .txt.
     * We probe the header to avoid misclassifying arbitrary .txt files. */
    size_t path_len = strlen(path);
    int is_lgbm_file = 0;
    if (path_len > 4 && strcmp(path + path_len - 4, ".txt") == 0) {
        FILE *probe = fopen(path, "r");
        if (probe) {
            char header[64];
            if (fgets(header, sizeof(header), probe)) {
                if (strncmp(header, "Tree", 4) == 0 ||
                    strncmp(header, "tree", 4) == 0 ||
                    strncmp(header, "tree_info", 9) == 0 ||
                    strstr(header, "LightGBM") != NULL) {
                    is_lgbm_file = 1;
                }
            }
            fclose(probe);
        }
    }

    if (is_lgbm_file) {
#ifdef AEGIS_USE_LIGHTGBM
        int out_num_iterations = 0;
        if (LGBM_BoosterCreateFromModelfile(path, &out_num_iterations, &model->lgbm_booster) == 0) {
            model->is_lgbm = 1;
            /* Try to read feature count from the first line if available. */
            FILE *fp = fopen(path, "r");
            if (fp) {
                char line[256];
                while (fgets(line, sizeof(line), fp)) {
                    if (strncmp(line, "max_feature_idx", 15) == 0) {
                        int idx = 0;
                        if (sscanf(line, "max_feature_idx=%d", &idx) == 1) {
                            model->n_features = idx + 1;
                        }
                        break;
                    }
                }
                fclose(fp);
            }
            return AEGIS_MODEL_OK;
        }
#endif
        return AEGIS_MODEL_ERR;
    }

    char *data = NULL;
    size_t data_len = 0;
    if (read_file(path, &data, &data_len) != 0) {
        return AEGIS_MODEL_ERR;
    }

    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) {
        fprintf(stderr, "model: failed to parse JSON model at %s: %s\n", path, cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown");
        return AEGIS_MODEL_ERR;
    }

    int rc = AEGIS_MODEL_OK;
    int n_trees = 0;

    cJSON *n_features = cJSON_GetObjectItemCaseSensitive(json, "n_features");
    cJSON *n_classes = cJSON_GetObjectItemCaseSensitive(json, "n_classes");
    cJSON *n_samples = cJSON_GetObjectItemCaseSensitive(json, "n_samples");
    cJSON *type = cJSON_GetObjectItemCaseSensitive(json, "type");
    cJSON *bias = cJSON_GetObjectItemCaseSensitive(json, "bias");
    cJSON *trees = cJSON_GetObjectItemCaseSensitive(json, "trees");

    if (cJSON_IsNumber(n_features)) model->n_features = (int)n_features->valuedouble;
    if (cJSON_IsNumber(n_classes)) {
        int nc = (int)n_classes->valuedouble;
        if (nc < 1 || nc > AEGIS_MAX_CLASSES) {
            fprintf(stderr, "model: n_classes %d out of bounds [1, %d]\n", nc, AEGIS_MAX_CLASSES);
            rc = AEGIS_MODEL_ERR;
            goto cleanup;
        }
        model->n_classes = nc;
    }
    if (cJSON_IsNumber(n_samples)) model->n_samples = (int)n_samples->valuedouble;
    if (cJSON_IsString(type)) {
        parse_type(type->valuestring, &model->type);
    }
    if (cJSON_IsNumber(bias)) model->bias = bias->valuedouble;

    if (!cJSON_IsArray(trees)) {
        rc = AEGIS_MODEL_ERR;
        goto cleanup;
    }

    n_trees = cJSON_GetArraySize(trees);
    if (n_trees < 1 || n_trees > AEGIS_MAX_TREES) {
        rc = AEGIS_MODEL_ERR;
        goto cleanup;
    }

    for (int i = 0; i < n_trees; i++) {
        cJSON *tree_obj = cJSON_GetArrayItem(trees, i);
        if (parse_tree(&model->trees[i], tree_obj) != AEGIS_MODEL_OK) {
            rc = AEGIS_MODEL_ERR;
            goto cleanup;
        }
        model->n_trees++;
    }

cleanup:
    cJSON_Delete(json);
    return rc;
}

void aegis_model_free(aegis_model_t *model) {
    if (!model) return;
#ifdef AEGIS_USE_LIGHTGBM
    if (model->is_lgbm && model->lgbm_booster) {
        LGBM_BoosterFree(model->lgbm_booster);
    }
#endif
    memset(model, 0, sizeof(*model));
}

/* --------------------------------------------------------------------------
 * Inference
 * -------------------------------------------------------------------------- */
double aegis_tree_predict(const aegis_tree_t *tree, const double *features, int n_features) {
    if (!tree || tree->n_nodes == 0 || !features) return 0.0;

    int idx = 0;
    int depth = 0;
    const int max_depth = tree->n_nodes * 2 + 1;
    while (idx >= 0 && idx < tree->n_nodes) {
        if (depth++ > max_depth) return 0.0;
        const aegis_tree_node_t *node = &tree->nodes[idx];
        if (node->is_leaf) {
            /* For classification, return probability of class 1. */
            if (node->value[1] > 0 || node->value[0] > 0) {
                double sum = node->value[0] + node->value[1];
                return sum > 0 ? node->value[1] / sum : 0.0;
            }
            return node->value[0];
        }
        if (node->left < 0 || node->right < 0 ||
            node->left >= tree->n_nodes || node->right >= tree->n_nodes) {
            return 0.0;
        }
        if (node->feature < 0 || node->feature >= n_features) {
            idx = node->left;
        } else if (features[node->feature] <= node->threshold) {
            idx = node->left;
        } else {
            idx = node->right;
        }
    }
    return 0.0;
}

double aegis_model_predict(aegis_model_t *model, const double *features, int n_features, double *out_proba) {
    if (!model) return 0.0;

#ifdef AEGIS_USE_LIGHTGBM
    if (model->is_lgbm && model->lgbm_booster) {
        int nf = (model->n_features > 0) ? model->n_features : n_features;
        double out_result[8] = {0};
        int64_t out_len = 0;
        int res = LGBM_BoosterPredictForMat(
            model->lgbm_booster,
            (const void *)features,
            C_API_DTYPE_FLOAT64,
            1,           /* nrow */
            nf,          /* ncol */
            1,           /* is_row_major */
            C_API_PREDICT_NORMAL,
            0,           /* start_iteration */
            -1,          /* num_iteration: all */
            "",          /* parameter */
            &out_len,
            out_result);

        if (res == 0 && out_len > 0) {
            double proba = out_result[0];
            if (proba < 0.0) proba = 0.0;
            if (proba > 1.0) proba = 1.0;
            if (out_proba) *out_proba = proba;
            return proba;
        }
        return 0.0;
    }
#endif

    if (model->n_trees == 0) return 0.0;

    int nf = (model->n_features > 0) ? model->n_features : n_features;
    double sum = 0.0;
    for (int i = 0; i < model->n_trees; i++) {
        sum += aegis_tree_predict(&model->trees[i], features, nf);
    }
    double avg = sum / model->n_trees;

    if (out_proba) {
        *out_proba = avg;
    }
    return avg;
}

double aegis_model_anomaly_score(aegis_model_t *model, const double *features, int n_features) {
    if (!model || model->n_trees == 0) return 0.5;

    int nf = (model->n_features > 0) ? model->n_features : n_features;
    double total_path = 0.0;
    for (int t = 0; t < model->n_trees; t++) {
        const aegis_tree_t *tree = &model->trees[t];
        if (tree->n_nodes == 0) continue;

        int idx = 0;
        int path_length = 0;
        int depth = 0;
        const int max_depth = tree->n_nodes * 2 + 1;
        while (idx >= 0 && idx < tree->n_nodes) {
            if (depth++ > max_depth) break;
            const aegis_tree_node_t *node = &tree->nodes[idx];
            if (node->is_leaf) break;
            path_length++;
            if (node->left < 0 || node->right < 0 ||
                node->left >= tree->n_nodes || node->right >= tree->n_nodes) {
                break;
            }
            if (node->feature < 0 || node->feature >= nf) {
                idx = node->left;
            } else if (features[node->feature] <= node->threshold) {
                idx = node->left;
            } else {
                idx = node->right;
            }
        }
        total_path += (double)path_length;
    }

    double avg_path = total_path / model->n_trees;
    /* Standard Isolation Forest anomaly score: s(x,n) = 2^(-E(h(x))/c(n))
     * where c(n) is the average path length of unsuccessful search in a BST. */
    int n_samples = model->n_samples > 2 ? model->n_samples : 256;
    double c_n = 2.0 * (log((double)(n_samples - 1)) + 0.5772156649) - (2.0 * (double)(n_samples - 1) / (double)n_samples);
    if (c_n <= 0.0) c_n = 1.0;
    double score = pow(2.0, -avg_path / c_n);
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    return score;
}
