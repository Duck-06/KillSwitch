# streamlit_app.py
# Streamlit GUI for CyberSecure IDS
# Features: Live Threat Feed, Blockchain view, Security Action Panel,
# Modal Metrics Dashboard, Confidence threshold slider, Explainability.

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import hashlib
import time
import importlib.util
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
import matplotlib.pyplot as plt

from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve, classification_report

# --------------- CONFIG ---------------
DATA_DIR = Path("data")
MODEL_PATH = DATA_DIR / "xgboost_intrusion_model_high_recall.pkl"
SCALER_PATH = DATA_DIR / "scaler.pkl"
PROCESSED_CSV = DATA_DIR / "input_flows.csv"

# Path to your uploaded blockchain implementation (adjust if needed)
BLOCKCHAIN_PY = Path("blockchain.py")

# Exact feature list (from your processed file)
FEATURE_COLS = [
    "Destination Port","Flow Duration","Total Fwd Packets","Total Length of Fwd Packets",
    "Fwd Packet Length Max","Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std",
    "Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std",
    "Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min",
    "Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min",
    "Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min",
    "Fwd Header Length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s",
    "Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std","Packet Length Variance",
    "FIN Flag Count","PSH Flag Count","ACK Flag Count","Average Packet Size","Subflow Fwd Bytes",
    "Init_Win_bytes_forward","Init_Win_bytes_backward","act_data_pkt_fwd","min_seg_size_forward",
    "Active Mean","Active Max","Active Min","Idle Mean","Idle Max","Idle Min"
]

LABEL_COLS_POSSIBLE = ["intrusion","label","Label","Label_binary","BinaryLabel"]

# --------------- UTILITIES ---------------
def load_blockchain_class(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"blockchain.py not found at {path}")
    spec = importlib.util.spec_from_file_location("user_blockchain_module", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "Blockchain"):
        raise AttributeError("blockchain.py does not define Blockchain class")
    return module.Blockchain

def compute_features_hash(features: Dict[str,Any]) -> str:
    s = json.dumps(features, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def summarize_features(features: Dict[str,Any], top_k:int=4) -> Dict[str,Any]:
    numeric = []
    for k,v in features.items():
        try:
            n = float(v)
            numeric.append((k, abs(n), v))
        except Exception:
            continue
    numeric.sort(key=lambda x: x[1], reverse=True)
    return {k: val for k,_,val in numeric[:top_k]}

# --------------- LOAD MODEL & DATA ---------------
@st.cache_resource
def load_model_scaler():
    if not MODEL_PATH.exists() or not SCALER_PATH.exists():
        raise FileNotFoundError("Place model and scaler under data/ as xgboost_intrusion_model_high_recall.pkl and scaler.pkl")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler

@st.cache_data
def load_demo_df():
    if PROCESSED_CSV.exists():
        return pd.read_csv(PROCESSED_CSV)
    return pd.DataFrame()

model, scaler = load_model_scaler()
demo_df = load_demo_df()

# --------------- PREDICTION / POSTPROCESS ---------------
def preprocess(df: pd.DataFrame):
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing features: {missing[:6]}{'...' if len(missing)>6 else ''}")
    X = df[FEATURE_COLS].astype(float).copy()
    Xs = scaler.transform(X.values)
    return pd.DataFrame(Xs, columns=FEATURE_COLS, index=df.index)

def decision_map(pred:int, prob:float):
    # prob = intrusion probability (0..1)
    confidence_not_intrusion = (1.0 - prob) * 100.0
    if pred == 0:
        return "Allow"
    intr_conf_pct = prob * 100.0
    if intr_conf_pct > 93.0:
        return "Block Source IP"
    if intr_conf_pct >= 60.0:
        return "Throttle Port Traffic"
    return "Quarantine Endpoint for Review"

# --------------- UI LAYOUT ---------------
st.set_page_config(page_title="CyberSecure - IDS Dashboard", layout="wide")
st.title("🛡 CyberSecure — Intrusion Detection Dashboard")

# Sidebar controls
st.sidebar.header("Controls")
threshold = 0.5
uploaded = st.sidebar.file_uploader("Upload flows CSV/XLSX (optional)", type=["csv","xlsx"])
append_blocks = st.sidebar.checkbox("Append detected intrusions to persistent chain.json", value=False)
show_preview_count = st.sidebar.number_input("Preview max rows", min_value=5, max_value=1000, value=50)


# Load data
if uploaded is not None:
    try:
        if uploaded.name.lower().endswith(".csv"):
            df_in = pd.read_csv(uploaded)
        else:
            df_in = pd.read_excel(uploaded)
    except Exception as e:
        st.sidebar.error(f"Could not read file: {e}")
        df_in = pd.DataFrame()
else:
    df_in = demo_df.copy()

if df_in is None:
    df_in = pd.DataFrame()

# Ensure time + src_ip for UI
if "time" not in df_in.columns:
    df_in["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
if "src_ip" not in df_in.columns:
    df_in["src_ip"] = [f"10.0.0.{10+i}" for i in range(len(df_in))]

# Tabs: Live feed, Blockchain, Metrics, Explainability
tab1, tab2, tab3, tab4 = st.tabs(["Live Threat Feed","Blockchain","Metrics Dashboard","Explainability"])

# --------------- Live Threat Feed ---------------
with tab1:
    st.subheader("Live Threat Feed")
    if df_in.empty:
        st.warning("No flow data. Upload a CSV/XLSX or place cicids2017_binary_processed.csv in data/")
    else:
        try:
            X = preprocess(df_in)
        except Exception as e:
            st.error(f"Preprocess error: {e}")
            st.stop()

        probs = model.predict_proba(X)[:, 1]   # intrusion probability
        preds = (probs >= threshold).astype(int)

        feed = df_in.copy()
        feed["intrusion_prob"] = probs
        feed["prediction"] = preds
        feed["prediction_label"] = feed["prediction"].map({0: "🟢 Benign", 1: "🔴 Intrusion"})

        # ✔ MAX confidence (element-wise)
        feed["confidence"] = np.maximum((1 - probs) * 100.0, probs * 100.0).round(6)

        # Suggested action based on intrusion probability
        feed["suggested_action"] = [
            decision_map(int(p), float(pr)) for p, pr in zip(feed["prediction"], feed["intrusion_prob"])
        ]

        # KPIs
        total = len(feed)
        intrusions = int(feed["prediction"].sum())
        benigns = total - intrusions
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Flows", total)
        c2.metric("Detected Intrusions", intrusions)
        c3.metric("Benign Flows", benigns)

        st.markdown(f"Showing up to *{show_preview_count}* rows")

        # ✔ FIXED — display correct columns including the new 'confidence'
        st.dataframe(
            feed[[
                "time",
                "src_ip",
                "prediction_label",
                "intrusion_prob",
                "confidence",
                "suggested_action"
            ]].head(show_preview_count),
            use_container_width=True
        )

        # Action counts
        st.subheader("Security Action Panel")
        action_counts = feed["suggested_action"].value_counts().to_dict()
        st.table(pd.DataFrame.from_dict(action_counts, orient="index", columns=["Count"]))

        # Optional: append intrusions to blockchain
        if append_blocks:
            Blockchain = load_blockchain_class(BLOCKCHAIN_PY)
            bc = Blockchain()
            appended = []

            for idx, row in feed.iterrows():
                if int(row["prediction"]) == 1:   # append only intrusions
                    features = {k: float(row[k]) if pd.notna(row[k]) else 0.0 for k in FEATURE_COLS}
                    fhash = compute_features_hash(features)
                    fsum = summarize_features(features, top_k=4)

                    event = {
                        "type": "ml_prediction",
                        "prediction": int(row["prediction"]),
                        "intrusion_probability": float(row["intrusion_prob"]),
                        "confidence": float(row["confidence"]),   # ✔ corrected field
                        "model_version": "xgboost_high_recall_v1",
                        "features_hash": fhash,
                        "feature_summary": fsum,
                        "timestamp": time.time()
                    }

                    block = bc.create_block(event)
                    appended.append(block)

            st.success(f"Appended {len(appended)} intrusion blocks to chain.json")
            if appended:
                st.dataframe(pd.DataFrame([
                    {"index": b["index"], "hash": b["hash"], "prev_hash": b["prev_hash"]}
                    for b in appended
                ]))

# --------------- Blockchain tab ---------------
with tab2:
    st.subheader("Blockchain (chain.json)")
    # Load local chain.json if exists using user's Blockchain (preferred)
    chain_path = Path("chain.json")
    if chain_path.exists():
        try:
            Blockchain = load_blockchain_class(BLOCKCHAIN_PY)
            bc = Blockchain()
            chain = bc.chain
        except Exception:
            # fallback: try to read raw file
            try:
                chain = json.loads(chain_path.read_text())
            except Exception as e:
                st.error(f"Could not load chain: {e}")
                chain = []
        # Show short summary table
        if chain:
            tbl = []
            for b in chain:
                ev = b.get("event", {})
                tbl.append({
                    "index": b.get("index"),
                    "ts": datetime.fromtimestamp(b.get("timestamp")).strftime("%Y-%m-%d %H:%M:%S"),
                    "type": ev.get("type"),
                    "prediction": ev.get("prediction"),
                    "intrusion_prob": ev.get("intrusion_probability"),
                    "feat_hash": (ev.get("features_hash") or "")[:16] + "...",
                    "hash": b.get("hash")[:16] + "...",
                    "prev_hash": b.get("prev_hash")[:16] + "..."
                })
            st.dataframe(pd.DataFrame(tbl), use_container_width=True)
            # Verify button
            if st.button("Verify chain integrity"):
                res = bc.verify_chain()
                if res.get("valid"):
                    st.success("Chain is valid 👍")
                else:
                    st.error(f"Chain invalid: {res}")
        else:
            st.info("chain.json exists but empty or could not be parsed.")
    else:
        st.info("No chain.json found in working directory. Append intrusions from Live Feed to create one.")

# ----------------- MODEL METRICS (IMPROVED — CM LEFT, BLUE HEATMAP) -----------------
with tab3:
    st.title("Model Performance")

    st.markdown(
        """
        In SOC operations, **missing an attack (false negative)** is more dangerous  
        than raising some extra alerts (false positives).  
        So we **optimize Recall for class 1 (Intrusion)**.
        """
    )

    # Path to the Excel report you generated (uploaded file path)
    METRICS_XLSX = "data/xgb_high_recall_full_metrics.xlsx"

    # Cached loader for the workbook so metrics block stays constant across reruns
    @st.cache_data
    def load_metrics_workbook(path):
        return pd.read_excel(path, sheet_name=None)

    # Load workbook safely (uses cached loader)
    try:
        xls = load_metrics_workbook(METRICS_XLSX)
    except Exception as e:
        st.error(f"Could not load metrics Excel at {METRICS_XLSX}: {e}")
        st.info("Upload a labeled dataset to the sidebar to compute metrics live.")
        st.stop()

    # Helper: best-effort sheet fetch
    def get_sheet(xls_dict, candidates):
        for c in candidates:
            if c in xls_dict:
                return xls_dict[c]
        # fuzzy search by lowercase containment
        for name, df in xls_dict.items():
            lname = name.lower()
            for c in candidates:
                if c.lower() in lname:
                    return df
        return None

    # Try to locate sheets
    threshold_df = get_sheet(xls, ["ThresholdSweep", "PerThreshold", "Thresholds"])
    roc_df = get_sheet(xls, ["ROC_points", "ROC", "roc"])
    pr_df = get_sheet(xls, ["PR_points", "PR", "PrecisionRecall", "PR"])
    cm_df = get_sheet(xls, ["ConfusionMatrix", "Confusion_Matrix", "ConfusionMatrix_default", "confusion"])
    classif_df = get_sheet(xls, ["ClassificationReport", "ClassReport", "Classification_Report"])
    preds_df = get_sheet(xls, ["PerSamplePredictions", "Predictions", "Predictions_export", "Per Sample", "predictions"])
    summary_df = get_sheet(xls, ["Summary", "SummaryAtDefault", "Summary_stats"])

    # Detect per-sample prob / true columns if preds present
    y_true = None
    y_prob = None
    prob_col = None
    true_col = None
    if preds_df is not None:
        cols = [c.lower() for c in preds_df.columns]
        for cand in [
            "_pred_prob_intrusion", "pred_prob_intrusion", "pred_prob", "prob_intrusion",
            "prob", "pred_probabilities", "probability", "intrusion_prob", "intrusion_probability"
        ]:
            if cand in cols:
                prob_col = preds_df.columns[cols.index(cand)]
                break
        for cand in ["intrusion", "label", "true", "true_label", "y_true", "actual", "ground_truth"]:
            if cand in cols:
                true_col = preds_df.columns[cols.index(cand)]
                break
        # fallback heuristics
        if prob_col is None:
            for i, c in enumerate(cols):
                if "prob" in c or "score" in c:
                    prob_col = preds_df.columns[i]
                    break
        if prob_col is None:
            numeric_cols = preds_df.select_dtypes(include=[float, int]).columns.tolist()
            if numeric_cols:
                prob_col = numeric_cols[-1]
        if true_col is None:
            for c in preds_df.select_dtypes(include=[int, float]).columns:
                vals = pd.Series(preds_df[c].dropna().unique())
                try:
                    if set(vals.astype(int).unique()).issubset({0, 1}):
                        true_col = c
                        break
                except Exception:
                    continue
        if true_col is None:
            for i, c in enumerate(cols):
                if "label" in c or "actual" in c or "ground" in c:
                    true_col = preds_df.columns[i]
                    break

        # assign arrays with safe casts
        if prob_col is not None:
            try:
                y_prob = preds_df[prob_col].astype(float).values
            except Exception:
                y_prob = pd.to_numeric(preds_df[prob_col], errors="coerce").values
        if true_col is not None:
            raw_true = preds_df[true_col]
            try:
                if raw_true.dtype == object:
                    # try mapping common strings -> 0/1
                    lower = raw_true.dropna().astype(str).str.lower()
                    mapping = {}
                    if any(s in ("benign","normal","no","false","neg","0") for s in lower.unique()):
                        mapping.update({k:0 for k in ["benign","normal","no","false","neg"]})
                    if any(s in ("intrusion","attack","yes","true","pos","1") for s in lower.unique()):
                        mapping.update({k:1 for k in ["intrusion","attack","yes","true","pos"]})
                    if mapping:
                        mapped = lower.map(mapping)
                        if mapped.notna().any():
                            y_true = mapped.astype('Int64').values
                if y_true is None:
                    y_tmp = pd.to_numeric(raw_true, errors="coerce").astype('Int64').values
                    if set(pd.Series(y_tmp).dropna().astype(int).unique()).issubset({0, 1}):
                        y_true = y_tmp
            except Exception:
                y_true = None

    # UI layout: put confusion matrix + heatmap on LEFT, controls + summary on RIGHT
    st.markdown("**Data source:** " + METRICS_XLSX)
    col_left, col_right = st.columns([2, 1])

    # -- LEFT: Confusion Matrix (table + blue heatmap) + curves below
    with col_left:
        st.subheader("Confusion Matrix")
        # normalization toggle (keep in left so user sees effect immediately)
        normalize_cm = st.checkbox("Normalize confusion matrix (rows)", value=False, key="cm_normalize_left")

        # Build confusion matrix (priority: preds_df -> cm_df -> live df_in)
        cm_to_display = None
        cm_index = ["Actual 0 (Benign)", "Actual 1 (Intrusion)"]
        cm_columns = ["Pred 0", "Pred 1"]

        if (y_true is not None) and (y_prob is not None):
            from sklearn.metrics import confusion_matrix
            y_pred_thr_for_cm = (y_prob >= 0.5).astype(int)  # initial default threshold for sheet display
            try:
                cm_to_display = confusion_matrix(y_true, y_pred_thr_for_cm)
            except Exception:
                cm_to_display = None
        elif cm_df is not None:
            try:
                tmp = cm_df.copy()
                if tmp.shape == (2, 2) and tmp.select_dtypes(include=[np.number]).shape == (2, 2):
                    cm_to_display = tmp.values.astype(int)
                    try:
                        cm_index = list(tmp.index.astype(str))
                        cm_columns = list(tmp.columns.astype(str))
                    except Exception:
                        pass
                else:
                    numeric = tmp.select_dtypes(include=[np.number])
                    if numeric.shape[1] >= 2:
                        cm_to_display = numeric.iloc[:2, :2].values.astype(int)
            except Exception:
                cm_to_display = None
        else:
            # try live data with model & df_in
            try:
                if not df_in.empty and model is not None:
                    X_live = preprocess(df_in)
                    probs_live = model.predict_proba(X_live)[:, 1]
                    preds_live = (probs_live >= 0.5).astype(int)
                    true_candidates = [c for c in df_in.columns if c.lower() in ("intrusion","label","true","true_label","actual")]
                    if true_candidates:
                        t_live = pd.to_numeric(df_in[true_candidates[0]], errors="coerce").astype('Int64').values
                        if set(pd.Series(t_live).dropna().astype(int).unique()).issubset({0, 1}):
                            from sklearn.metrics import confusion_matrix
                            cm_to_display = confusion_matrix(t_live, preds_live)
            except Exception:
                cm_to_display = None

        if cm_to_display is not None:
            cm_display_df = pd.DataFrame(cm_to_display, index=cm_index, columns=cm_columns)
            st.table(cm_display_df)

            # draw attractive blue heatmap using matplotlib Blues cmap
            try:
                disp_cm = cm_to_display.astype(float)
                if normalize_cm:
                    row_sums = disp_cm.sum(axis=1, keepdims=True)
                    row_sums[row_sums == 0] = 1
                    disp = disp_cm / row_sums
                else:
                    disp = disp_cm

                fig, ax = plt.subplots(figsize=(5, 4))
                im = ax.imshow(disp, interpolation='nearest', aspect='auto', cmap="Blues")
                # colorbar (subtle)
                cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
                cbar.ax.tick_params(labelsize=8)

                # Annotate cells with dynamic text color for readability
                thresh = disp.max() / 2.0 if disp.max() != 0 else 0.5
                for i in range(disp.shape[0]):
                    for j in range(disp.shape[1]):
                        v = disp[i, j]
                        if normalize_cm:
                            txt = f"{v:.2f}"
                        else:
                            txt = f"{int(v)}"
                        color = "white" if v > thresh else "black"
                        ax.text(j, i, txt, ha="center", va="center", fontsize=12, color=color, fontweight='bold')

                ax.set_xticks(np.arange(len(cm_columns)))
                ax.set_xticklabels(cm_columns, rotation=45, ha="right", fontsize=10)
                ax.set_yticks(np.arange(len(cm_index)))
                ax.set_yticklabels(cm_index, fontsize=10)
                ax.set_title("Confusion Matrix" + (" (normalized)" if normalize_cm else ""), fontsize=14, pad=12)
                # soften spines for nicer look
                for spine in ax.spines.values():
                    spine.set_visible(False)
                ax.set_xlabel("")
                ax.set_ylabel("")
                fig.tight_layout()
                st.pyplot(fig)
            except Exception as e:
                st.warning(f"Could not render confusion heatmap: {e}")

        else:
            st.info("Confusion matrix not available from the report or computed predictions.")

        # Place ROC, PR and Threshold Sweep below confusion matrix on the left
        st.markdown("---")
        st.subheader("ROC Curve")
        if roc_df is not None and {"fpr", "tpr"}.issubset(roc_df.columns):
            fig, ax = plt.subplots()
            ax.plot(roc_df["fpr"], roc_df["tpr"], label="ROC (sheet)", linewidth=2)
            if y_true is not None and y_prob is not None:
                try:
                    from sklearn.metrics import roc_auc_score
                    ax.legend(title=f"AUC={roc_auc_score(y_true, y_prob):.4f}")
                except Exception:
                    ax.legend()
            else:
                ax.legend()
            ax.plot([0, 1], [0, 1], linestyle="--", linewidth=1, color="gray")
            ax.set_xlabel("False Positive Rate")
            ax.set_ylabel("True Positive Rate")
            fig.tight_layout()
            st.pyplot(fig)
        elif (y_true is not None) and (y_prob is not None):
            from sklearn.metrics import roc_curve, roc_auc_score
            fpr, tpr, _ = roc_curve(y_true, y_prob)
            auc_val = roc_auc_score(y_true, y_prob)
            fig, ax = plt.subplots()
            ax.plot(fpr, tpr, label=f"AUC={auc_val:.4f}", linewidth=2)
            ax.plot([0, 1], [0, 1], linestyle="--", linewidth=1, color="gray")
            ax.set_xlabel("False Positive Rate")
            ax.set_ylabel("True Positive Rate")
            fig.tight_layout()
            st.pyplot(fig)
        else:
            st.info("ROC points not found in Excel and per-sample predictions missing.")

        st.subheader("Precision-Recall Curve")
        if pr_df is not None and {"recall", "precision"}.issubset(pr_df.columns):
            fig, ax = plt.subplots()
            ax.plot(pr_df["recall"], pr_df["precision"], linewidth=2)
            ax.set_xlabel("Recall")
            ax.set_ylabel("Precision")
            fig.tight_layout()
            st.pyplot(fig)
        elif (y_true is not None) and (y_prob is not None):
            from sklearn.metrics import precision_recall_curve, average_precision_score
            prec, rec, _ = precision_recall_curve(y_true, y_prob)
            ap = average_precision_score(y_true, y_prob)
            fig, ax = plt.subplots()
            ax.plot(rec, prec, label=f"AP={ap:.4f}", linewidth=2)
            ax.set_xlabel("Recall")
            ax.set_ylabel("Precision")
            ax.legend()
            fig.tight_layout()
            st.pyplot(fig)
        else:
            st.info("PR points not found in Excel and per-sample predictions missing.")

    # -- RIGHT: Summary, controls, KPIs, classification report, misclassified samples
    with col_right:
        st.subheader("Summary & Controls")
        if summary_df is not None and not summary_df.empty:
            try:
                st.table(summary_df.head(1).T.rename(columns={0: "value"}))
            except Exception:
                st.dataframe(summary_df.head(1))
        else:
            st.info("No Summary sheet in Excel.")

# --------------- EXPLAINABILITY (TAB4 — robust, no-caching SHAP + feature importance) ---------------
with tab4:
    st.subheader("Explainability")

    # Quick guard: require data and model
    if df_in.empty:
        st.info("No data loaded. Upload flows or use demo data to enable explainability.")
    else:
        # Ensure feature columns exist
        missing = [c for c in FEATURE_COLS if c not in df_in.columns]
        if missing:
            st.error(f"Missing feature columns required for explainability: {missing[:10]}{'...' if len(missing)>10 else ''}")
            st.stop()

        # --- 1) Fast global feature importance from model (if available) ---
        st.markdown("### Global feature importance (model)")
        if hasattr(model, "feature_importances_"):
            try:
                fi = pd.Series(model.feature_importances_, index=FEATURE_COLS).sort_values(ascending=False)
                st.write("Top features by model.feature_importances_")
                st.bar_chart(fi.head(20))
            except Exception as e:
                st.warning(f"Could not render model.feature_importances_: {e}")
        else:
            st.info("Model does not expose `feature_importances_`. SHAP (below) will be used for explainability if available.")

        # --- 2) SHAP explainability (global + per-sample) ---
        st.markdown("### SHAP explainability (tree-aware preferred)")

        try:
            import shap
        except Exception:
            st.error("SHAP is not installed in your environment. Install with `pip install shap` to enable SHAP explainability.")
            st.stop()

        # Prepare data for SHAP: sampled background (no caching here for simplicity & reliability)
        def prepare_shap_data(df, feature_cols, nsamples=300):
            X = df[feature_cols].astype(float).copy()
            if len(X) > nsamples:
                X_ref = X.sample(n=nsamples, random_state=0)
            else:
                X_ref = X
            return X_ref, X

        X_ref, X_full = prepare_shap_data(df_in, FEATURE_COLS, nsamples=300)

        # Build a SHAP explainer (prefer TreeExplainer for tree models)
        explainer = None
        try:
            explainer = shap.TreeExplainer(model, data=X_ref, feature_perturbation="interventional")
        except Exception:
            try:
                explainer = shap.Explainer(model.predict, X_ref)
            except Exception:
                explainer = None

        if explainer is None:
            st.info("Could not create a SHAP explainer for this model. Only model.feature_importances_ is shown above.")
        else:
            # Compute SHAP values for the sampled dataset (no caching)
            try:
                shap_values_full = explainer(X_full)
            except Exception as e:
                st.warning(f"SHAP computation for dataset failed: {e}")
                shap_values_full = None

            # ---- Global SHAP summary ----
            st.markdown("#### Global SHAP feature importance (mean |SHAP value|)")
            if shap_values_full is not None:
                try:
                    # Try shap's bar plot (preferred)
                    try:
                        shap.plots.bar(shap_values_full, show=False)
                        import matplotlib.pyplot as _plt
                        fig = _plt.gcf()
                        fig.tight_layout()
                        st.pyplot(fig)
                        _plt.clf()
                    except Exception:
                        # fallback: compute mean abs and show a simple bar_chart
                        mean_abs = np.abs(shap_values_full.values).mean(axis=0)
                        mean_abs_series = pd.Series(mean_abs, index=FEATURE_COLS).sort_values(ascending=False)
                        st.bar_chart(mean_abs_series.head(25))
                except Exception as e:
                    st.warning(f"Could not render global SHAP summary: {e}")
            else:
                st.info("SHAP values not available for global summary.")

            st.markdown("---")
            # ---- Per-sample explanation controls ----
            st.markdown("#### Explain a single flow (per-sample)")

            # Limit selectable indices for UI responsiveness
            max_choices = min(500, len(X_full))
            options = list(X_full.index[:max_choices])
            if not options:
                st.info("No rows available for per-sample explainability.")
            else:
                idx_choice = st.selectbox("Select sample index to explain (first rows)", options=options, index=0)

                # Get the sample as DataFrame (1 row)
                sample_X = X_full.loc[[idx_choice]]

                # Show model prediction & probability if possible
                # SHAP per-sample explanation (waterfall preferred, with robust fallbacks)
                st.markdown("##### SHAP per-sample explanation (waterfall / force / table fallback)")

                try:
                    # Compute SHAP for the single sample (uncached; usually fast)
                    sv_single = explainer(sample_X)  # shap.Explanation-like

                    # 1) Try matplotlib waterfall (preferred)
                    rendered = False
                    try:
                        import matplotlib.pyplot as _plt
                        shap.plots.waterfall(sv_single[0], show=False)
                        fig = _plt.gcf()
                        fig.tight_layout()
                        st.pyplot(fig)
                        _plt.clf()
                        rendered = True
                    except Exception:
                        rendered = False

                    if not rendered:
                        # 2) Try JS force_plot (embed as HTML). Works if SHAP supports HTML export.
                        try:
                            # Build force plot (this returns a JS/HTML object in recent SHAP)
                            base_val = explainer.expected_value if hasattr(explainer, "expected_value") else None
                            # shap.force_plot signature varies; try common patterns
                            if hasattr(sv_single, "values"):
                                sv_vals = sv_single.values[0]
                            else:
                                sv_vals = sv_single[0].values
                            # prefer shap.force_plot with matplotlib=False to get HTML
                            fp = shap.force_plot(base_val, sv_vals, sample_X.iloc[0], matplotlib=False)
                            import streamlit.components.v1 as components
                            # If fp is an object with .html(), use that; otherwise try to convert to str
                            html = None
                            try:
                                html = fp.html()
                            except Exception:
                                try:
                                    html = str(fp)
                                except Exception:
                                    html = None
                            if html is not None:
                                components.html(html, height=360, scrolling=True)
                                rendered = True
                        except Exception:
                            rendered = False

                    if not rendered:
                        # 3) Last fallback — table of top contributing features (by absolute SHAP)
                        try:
                            if hasattr(sv_single, "values"):
                                vals = sv_single.values[0]
                            else:
                                vals = sv_single[0].values
                            contribs = pd.DataFrame({
                                "feature": FEATURE_COLS,
                                "value": sample_X.iloc[0].values,
                                "shap": vals
                            })
                            contribs["abs_shap"] = contribs["shap"].abs()
                            contribs = contribs.sort_values("abs_shap", ascending=False).drop(columns="abs_shap")
                            st.dataframe(contribs.reset_index(drop=True).head(20))
                        except Exception as e:
                            st.warning(f"Could not present per-sample SHAP contributions: {e}")

                except Exception as e:
                    st.warning(f"Per-sample SHAP explanation failed: {e}")
                    # fallback: show top model importances and the sample values
                    try:
                        if hasattr(model, "feature_importances_"):
                            fi = pd.Series(model.feature_importances_, index=FEATURE_COLS).sort_values(ascending=False)
                            top_feats = fi.head(10).index.tolist()
                            st.write("Top model-important features — sample values:")
                            st.table(sample_X[top_feats].T.rename(columns={idx_choice: "value"}))
                    except Exception:
                        pass

            st.markdown("---")
            # ---- SHAP dependence plot (feature interaction) ----
            st.markdown("#### SHAP dependence (feature interaction)")
            try:
                feat_for_dependence = st.selectbox("Choose feature for dependence plot", options=FEATURE_COLS, index=0)
                if shap_values_full is not None:
                    try:
                        # shap.plots.scatter will draw to matplotlib in many versions
                        shap.plots.scatter(shap_values_full[:, feat_for_dependence], color=shap_values_full)
                        import matplotlib.pyplot as _plt
                        fig = _plt.gcf()
                        fig.tight_layout()
                        st.pyplot(fig)
                        _plt.clf()
                    except Exception as e:
                        st.info(f"Could not render SHAP dependence plot: {e}")
                else:
                    st.info("SHAP values not available to draw dependence plot.")
            except Exception as e:
                st.info(f"SHAP dependence control failed: {e}")

        # End of SHAP section

