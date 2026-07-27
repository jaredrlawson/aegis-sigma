/*
 * Aegis-SIGMA Shield/Soul — JSON tree model inference
 *
 * Loads tree-based ML models (RandomForest / LightGBM / IsolationForest)
 * exported from Python as JSON and runs inference in pure C.
 */

#ifndef AEGIS_MODEL_H
#define AEGIS_MODEL_H

#include <stddef.h>

#define AEGIS_MODEL_OK 0
#define AEGIS_MODEL_ERR -1

#define AEGIS_MAX_FEATURES 64
#define AEGIS_MAX_TREES 256
#define AEGIS_MAX_NODES 4096
#define AEGIS_MAX_CLASSES 8

typedef enum {
    AEGIS_TREE_REGRESSION,
    AEGIS_TREE_CLASSIFICATION,
    AEGIS_TREE_ISOLATION,
} aegis_tree_type_t;

typedef struct {
    int feature;
    double threshold;
    int left;
    int right;
    double value[AEGIS_MAX_CLASSES];
    int is_leaf;
} aegis_tree_node_t;

typedef struct {
    aegis_tree_node_t nodes[AEGIS_MAX_NODES];
    int n_nodes;
    aegis_tree_type_t type;
} aegis_tree_t;

typedef struct {
    char name[64];
    aegis_tree_t trees[AEGIS_MAX_TREES];
    int n_trees;
    int n_features;
    int n_classes;
    int n_samples;
    aegis_tree_type_t type;
    double bias;

    /* LightGBM native C API integration. */
    int is_lgbm;
    void *lgbm_booster;
} aegis_model_t;

int  aegis_model_load(aegis_model_t *model, const char *path);
void aegis_model_free(aegis_model_t *model);

/* Classification / regression inference. */
double aegis_tree_predict(const aegis_tree_t *tree, const double *features, int n_features);
double aegis_model_predict(aegis_model_t *model, const double *features, int n_features, double *out_proba);

/* Isolation Forest anomaly score. */
double aegis_model_anomaly_score(aegis_model_t *model, const double *features, int n_features);

#endif /* AEGIS_MODEL_H */
