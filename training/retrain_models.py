#!/usr/bin/env python3
"""
Automated retrain for C engine models (shield.json + soul.json).
Reads labeled training data, trains Random Forest + Isolation Forest,
exports to Aegis JSON Tree format compatible with the C engine.

Runs nightly via cron during training window (11PM-6AM).
"""
import json
import math
import os
import sys
import time
from datetime import datetime

import numpy as np

# Try scikit-learn, fall back to manual implementation
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("[WARN] scikit-learn not available, using manual tree implementation")

N_FEATURES = 30
N_TREES = 100
MAX_DEPTH = 10

MODELS_DIR = os.environ.get("MODELS_DIR", "models")
TRAINING_DIR = os.environ.get("TRAINING_DIR", "training_data")
BRAIN_DB = os.environ.get("BRAIN_DB", "brain.sqlite")


def load_training_data():
    """Load all available training data sources."""
    all_features = []
    all_labels = []

    # 1. CSIC synthetic dataset
    csic_feat = os.path.join(TRAINING_DIR, "csic_features.npy")
    csic_lab = os.path.join(TRAINING_DIR, "csic_labels.npy")
    if os.path.exists(csic_feat) and os.path.exists(csic_lab):
        f = np.load(csic_feat)
        l = np.load(csic_lab)
        all_features.append(f)
        all_labels.append(l)
        print(f"  Loaded CSIC dataset: {len(l)} samples")

    # 2. Teacher labels from brain.sqlite
    try:
        import sqlite3
        conn = sqlite3.connect(BRAIN_DB)
        cur = conn.cursor()
        cur.execute("SELECT features_json, teacher_verdict FROM teacher_labels ORDER BY id DESC LIMIT 50000")
        rows = cur.fetchall()
        conn.close()
        if rows:
            feats = []
            labs = []
            for features_json, label in rows:
                try:
                    f = json.loads(features_json)
                    if len(f) == N_FEATURES:
                        feats.append(f)
                        labs.append(label)
                except:
                    continue
            if feats:
                all_features.append(np.array(feats, dtype=np.float32))
                all_labels.append(np.array(labs, dtype=np.int32))
                print(f"  Loaded teacher labels: {len(labs)} samples")
    except Exception as e:
        print(f"  No teacher labels available: {e}")

    # 3. Security events from brain.sqlite
    try:
        import sqlite3
        from datetime import datetime, timedelta

        sys.path.insert(0, os.path.dirname(__file__))
        from generate_training_data import extract_from_security_events, features_from_event

        rows = extract_from_security_events(BRAIN_DB)
        if rows:
            feats = []
            labs = []
            for row in rows:
                f, l = features_from_event(row)
                feats.append(f)
                labs.append(l)
            all_features.append(np.array(feats, dtype=np.float32))
            all_labels.append(np.array(labs, dtype=np.int32))
            print(f"  Loaded security events: {len(labs)} samples")
    except Exception as e:
        print(f"  No security events: {e}")

    if not all_features:
        print("[ERROR] No training data available!")
        sys.exit(1)

    X = np.vstack(all_features)
    y = np.concatenate(all_labels)
    print(f"  Total training samples: {len(y)} (hostile={sum(y)}, benign={len(y)-sum(y)})")
    return X, y


def tree_to_json(tree, feature_names=None):
    """Convert a scikit-learn tree to Aegis JSON Tree format.
    
    Builds nodes in pre-order (root first) so index 0 is always the root.
    The C engine starts at nodes[0] and traverses left/right indices.
    """
    tree_data = tree.tree_
    nodes = []

    def recurse(node_id):
        """Appends nodes in pre-order (root before children)."""
        if tree_data.children_left[node_id] == tree_data.children_right[node_id]:
            # Leaf node
            value = tree_data.value[node_id][0].tolist()
            total = sum(value)
            if total > 0:
                value = [v / total for v in value]
            my_idx = len(nodes)
            nodes.append({
                "feature": -1,
                "threshold": 0.0,
                "left": -1,
                "right": -1,
                "is_leaf": 1,
                "value": value
            })
            return my_idx
        
        # Internal node — append self first, then children
        feature = int(tree_data.feature[node_id])
        threshold = float(tree_data.threshold[node_id])
        my_idx = len(nodes)
        nodes.append({
            "feature": feature,
            "threshold": round(threshold, 6),
            "left": -1,  # placeholder
            "right": -1,  # placeholder
            "is_leaf": 0,
            "value": [0.0, 0.0]
        })
        
        left_idx = recurse(tree_data.children_left[node_id])
        right_idx = recurse(tree_data.children_right[node_id])
        
        nodes[my_idx]["left"] = left_idx
        nodes[my_idx]["right"] = right_idx
        return my_idx

    recurse(0)
    return nodes


def train_and_export(X, y):
    """Train models and export to Aegis JSON format."""
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # --- Train Shield (Random Forest Classifier) ---
    print("\n[Shield] Training Random Forest Classifier...")
    if HAS_SKLEARN:
        clf = RandomForestClassifier(
            n_estimators=N_TREES,
            max_depth=MAX_DEPTH,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        clf.fit(X, y)

        # Export to Aegis JSON format
        trees = []
        for i, est in enumerate(clf.estimators_):
            tree_nodes = tree_to_json(est)
            trees.append({"nodes": tree_nodes})

        shield = {
            "type": "classification",
            "n_features": N_FEATURES,
            "n_classes": 2,
            "n_samples": len(y),
            "trees": trees,
            "bias": 0.0,
            "version": timestamp,
            "accuracy": float(clf.score(X, y)),
        }
        print(f"  Accuracy: {shield['accuracy']:.4f}")
    else:
        # Manual training fallback - create synthetic trees
        shield = train_manual_rf(X, y, timestamp)

    # --- Train Soul (Isolation Forest) ---
    print("[Soul] Training Isolation Forest...")
    if HAS_SKLEARN:
        iso = IsolationForest(
            n_estimators=N_TREES,
            contamination=0.1,
            max_samples=256,
            random_state=42,
            n_jobs=-1
        )
        iso.fit(X)

        trees = []
        for i, est in enumerate(iso.estimators_):
            tree_nodes = tree_to_json(est)
            trees.append({"nodes": tree_nodes})

        soul = {
            "type": "isolation_forest",
            "n_features": N_FEATURES,
            "n_classes": 2,
            "n_samples": N_TREES * 256,
            "trees": trees,
            "bias": 0.0,
            "version": timestamp,
        }
    else:
        soul = train_manual_iforest(X, y, timestamp)

    # --- Export ---
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Backup existing models
    ts = int(time.time())
    for fname in ["shield.json", "soul.json"]:
        src = os.path.join(MODELS_DIR, fname)
        if os.path.exists(src):
            bak = os.path.join(MODELS_DIR, f"backup-{ts}", fname)
            os.makedirs(os.path.dirname(bak), exist_ok=True)
            import shutil
            shutil.copy2(src, bak)

    # Write new models
    shield_path = os.path.join(MODELS_DIR, "shield.json")
    soul_path = os.path.join(MODELS_DIR, "soul.json")

    with open(shield_path, "w") as f:
        json.dump(shield, f)
    print(f"  Wrote {shield_path} ({os.path.getsize(shield_path)} bytes)")

    with open(soul_path, "w") as f:
        json.dump(soul, f)
    print(f"  Wrote {soul_path} ({os.path.getsize(soul_path)} bytes)")

    return shield, soul


def train_manual_rf(X, y, timestamp):
    """Manual Random Forest when scikit-learn is unavailable."""
    print("  Using manual tree training...")
    trees = []
    n_samples = len(y)

    for t in range(N_TREES):
        # Bootstrap sample
        idx = np.random.choice(n_samples, n_samples, replace=True)
        X_boot, y_boot = X[idx], y[idx]

        # Simple decision stump trees
        nodes = []
        for d in range(min(MAX_DEPTH, N_FEATURES)):
            best_feat = np.random.randint(N_FEATURES)
            best_thresh = np.median(X_boot[:, best_feat])

            left_mask = X_boot[:, best_feat] <= best_thresh
            right_mask = ~left_mask

            left_val = [0.0, 0.0]
            right_val = [0.0, 0.0]
            if left_mask.any():
                lc = np.sum(y_boot[left_mask] == 0)
                lh = np.sum(y_boot[left_mask] == 1)
                lt = lc + lh
                left_val = [lc / lt, lh / lt]
            if right_mask.any():
                rc = np.sum(y_boot[right_mask] == 0)
                rh = np.sum(y_boot[right_mask] == 1)
                rt = rc + rh
                right_val = [rc / rt, rh / rt]

            left_idx = len(nodes) + 1
            right_idx = len(nodes) + 2

            nodes.append({
                "feature": int(best_feat),
                "threshold": round(float(best_thresh), 6),
                "left": left_idx,
                "right": right_idx,
                "is_leaf": 0,
                "value": [0.0, 0.0]
            })

            if d == min(MAX_DEPTH, N_FEATURES) - 1:
                nodes.append({"feature": -1, "threshold": 0, "left": -1, "right": -1, "is_leaf": 1, "value": left_val})
                nodes.append({"feature": -1, "threshold": 0, "left": -1, "right": -1, "is_leaf": 1, "value": right_val})
                break

        trees.append({"nodes": nodes})

    return {
        "type": "classification",
        "n_features": N_FEATURES,
        "n_classes": 2,
        "n_samples": n_samples,
        "trees": trees,
        "bias": 0.0,
        "version": timestamp,
    }


def train_manual_iforest(X, y, timestamp):
    """Manual Isolation Forest when scikit-learn is unavailable."""
    print("  Using manual isolation forest...")
    trees = []

    for t in range(N_TREES):
        idx = np.random.choice(len(y), min(256, len(y)), replace=False)
        X_sub = X[idx]

        nodes = []
        max_depth = int(math.ceil(math.log2(256)))

        def build_tree(depth=0):
            if depth >= max_depth or len(X_sub) < 2:
                leaf_val = float(depth) / max_depth
                nodes.append({"feature": -1, "threshold": 0, "left": -1, "right": -1, "is_leaf": 1, "value": [leaf_val, 0]})
                return len(nodes) - 1

            feat = np.random.randint(N_FEATURES)
            lo, hi = X_sub[:, feat].min(), X_sub[:, feat].max()
            if lo == hi:
                thresh = lo
            else:
                thresh = np.random.uniform(lo, hi)

            left_idx = build_tree(depth + 1)
            right_idx = build_tree(depth + 1)

            nodes.append({"feature": int(feat), "threshold": round(float(thresh), 6), "left": left_idx, "right": right_idx, "is_leaf": 0, "value": [0.0, 0.0]})
            return len(nodes) - 1

        build_tree()
        trees.append({"nodes": nodes})

    return {
        "type": "isolation_forest",
        "n_features": N_FEATURES,
        "n_classes": 2,
        "n_samples": N_TREES * 256,
        "trees": trees,
        "bias": 0.0,
        "version": timestamp,
    }


def verify_models(shield, soul):
    """Quick sanity check on exported models."""
    errors = []

    if shield["n_features"] != N_FEATURES:
        errors.append(f"Shield n_features={shield['n_features']}, expected {N_FEATURES}")
    if soul["n_features"] != N_FEATURES:
        errors.append(f"Soul n_features={soul['n_features']}, expected {N_FEATURES}")
    if len(shield["trees"]) < 10:
        errors.append(f"Shield has only {len(shield['trees'])} trees, expected {N_TREES}")
    if len(soul["trees"]) < 10:
        errors.append(f"Soul has only {len(soul['trees'])} trees, expected {N_TREES}")

    # Check first tree has valid structure
    for name, model in [("Shield", shield), ("Soul", soul)]:
        tree = model["trees"][0]
        if not tree["nodes"]:
            errors.append(f"{name} first tree is empty")
        elif tree["nodes"][0].get("is_leaf") and len(tree["nodes"]) == 1:
            errors.append(f"{name} first tree is a single leaf (no splits)")

    if errors:
        print(f"\n[VERIFY FAILED]")
        for e in errors:
            print(f"  - {e}")
        return False
    else:
        print("\n[VERIFY OK] Models look valid")
        return True


def main():
    print(f"=== Aegis-SIGMA Model Retrain ===")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"scikit-learn: {'available' if HAS_SKLEARN else 'NOT available (manual fallback)'}")

    X, y = load_training_data()
    shield, soul = train_and_export(X, y)

    if verify_models(shield, soul):
        print("\nRetrain complete. Restart aegis-c to load new models.")
    else:
        print("\nRetrain completed with warnings. Check model output.")
        sys.exit(1)


if __name__ == "__main__":
    main()
