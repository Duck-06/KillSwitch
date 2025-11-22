# predict_offline.py — 100% offline ML + Blockchain logging

import pandas as pd
import joblib
import time
from pathlib import Path
from blockchain import Blockchain

# ---------------- CONFIG ----------------
DATA_DIR = Path("data")
MODEL_PATH = DATA_DIR / "xgboost_intrusion_model_high_recall.pkl"
SCALER_PATH = DATA_DIR / "scaler.pkl"
PROCESSED_CSV = DATA_DIR / "cicids2017_binary_processed.csv"

INPUT_FILE = "inputs.csv"   # <-- change this to your CSV/XLSX file
# ----------------------------------------

# Load model + scaler
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Load training feature names
processed_df = pd.read_csv(PROCESSED_CSV)
train_features = processed_df.drop(columns=["intrusion"]).columns.tolist()

# Load input file (CSV or Excel)
if INPUT_FILE.lower().endswith(".csv"):
    df = pd.read_csv(INPUT_FILE)
elif INPUT_FILE.lower().endswith(".xlsx"):
    df = pd.read_excel(INPUT_FILE)
else:
    raise ValueError("Only CSV or XLSX supported.")

# Validate columns
missing = set(train_features) - set(df.columns)
if missing:
    raise ValueError(f"Missing columns: {missing}")

# Keep only required columns
df = df[train_features]

# Scale
scaled = scaler.transform(df)

# Predict
probs = model.predict_proba(scaled)[:, 1]
labels = model.predict(scaled)

# Initialize blockchain
bc = Blockchain()

summary = []

# Append one block per flow
for i, row in df.iterrows():
    prob = float(probs[i])
    pred = int(labels[i])
    confidence = (1 - prob)

    event = {
        "type": "ml_prediction",
        "prediction": pred,
        "intrusion_probability": prob,
        "benign_probablity": confidence,
        "confidence_percentage": max(confidence * 100,prob*100),
        "timestamp": time.time(),
        "model_version": "xgboost_high_recall_v1"
    }

    block = bc.create_block(event)
    summary.append(block)

print("\n=== Appended blocks ===")
print(pd.DataFrame(summary)[["index","hash","prev_hash"]])

# Save summary CSV
pd.DataFrame(summary).to_csv("prediction_block_summary.csv", index=False)
print("\nSaved: prediction_block_summary.csv")
