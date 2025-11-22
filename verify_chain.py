#!/usr/bin/env python3
"""
verify_chain.py

Offline verification tool for chain.json created by your blockchain.
- Verifies chain integrity (prev_hash links + recomputed hash)
- Optionally verifies block features by recomputing features_hash using features_store.csv.gz
Usage:
  python verify_chain.py                 # verify chain only
  python verify_chain.py --report out.json
  python verify_chain.py --verify-block 5   # verify block index 5 features (requires features_store.csv.gz)
"""

import argparse
import json
import sys
import gzip
import csv
import hashlib
from pathlib import Path
import importlib.util
from typing import Dict, Any, Optional

# === CONFIG: change paths if needed ===
CHAIN_JSON = Path("chain.json")                       # chain produced by blockchain.py
BLOCKCHAIN_PY = Path("/mnt/data/blockchain.py")       # path to your blockchain implementation (as provided)
FEATURE_STORE_GZ = Path("features_store.csv.gz")      # gz csv produced by predict_offline.py (optional)
# ======================================

def load_blockchain_class(path: Path):
    """Dynamically import a Blockchain class from the given python file path."""
    if not path.exists():
        raise FileNotFoundError(f"blockchain file not found at: {path}")
    spec = importlib.util.spec_from_file_location("user_blockchain_module", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    if not hasattr(mod, "Blockchain"):
        raise AttributeError("Loaded module does not define 'Blockchain' class.")
    return mod.Blockchain

def recompute_hash(block: Dict[str, Any]) -> str:
    """
    Recompute the SHA256 hash used in blockchain.py:
    - Exclude the 'hash' field and serialize with sorted keys and separators=(',', ':')
    """
    block_copy = {k: block[k] for k in sorted(block) if k != "hash"}
    block_str = json.dumps(block_copy, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(block_str.encode("utf-8")).hexdigest()

def verify_chain(chain: list) -> Dict[str, Any]:
    """
    Verify the whole chain list (loaded from chain.json).
    Returns {"valid": True} or {"valid": False, "broken_at_index": i, "reason": "...", "details": {...}}
    """
    if not isinstance(chain, list) or len(chain) == 0:
        return {"valid": False, "reason": "chain.json is empty or invalid format"}

    for i in range(1, len(chain)):
        prev = chain[i-1]
        cur = chain[i]
        # 1) prev_hash must match previous hash
        if cur.get("prev_hash") != prev.get("hash"):
            return {
                "valid": False,
                "broken_at_index": i,
                "reason": "prev_hash mismatch",
                "details": {"expected_prev_hash": prev.get("hash"), "found_prev_hash": cur.get("prev_hash")}
            }
        # 2) recompute hash and compare
        recomputed = recompute_hash(cur)
        if recomputed != cur.get("hash"):
            return {
                "valid": False,
                "broken_at_index": i,
                "reason": "hash mismatch",
                "details": {"recomputed": recomputed, "stored": cur.get("hash")}
            }
    return {"valid": True}

def find_feature_row_by_hash(features_hash: str) -> Optional[Dict[str, Any]]:
    """
    Look up full features in features_store.csv.gz by features_hash.
    features_store.csv.gz format expected:
      features_hash,row_index,features_json
    Returns the deserialized features dict if found, else None.
    """
    if not FEATURE_STORE_GZ.exists():
        raise FileNotFoundError(f"{FEATURE_STORE_GZ} not found in working directory.")
    with gzip.open(FEATURE_STORE_GZ, "rt", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 3:
                continue
            fh = row[0]
            if fh == features_hash:
                # third column is a JSON string - try to parse
                try:
                    features_json = row[2]
                    # If features_json is quoted or escaped, this still handles it
                    return json.loads(features_json)
                except Exception:
                    # fallback: try joining remainder of row and parse
                    try:
                        joined = ",".join(row[2:])
                        return json.loads(joined)
                    except Exception:
                        return None
    return None

def compute_features_hash(features: Dict[str, Any]) -> str:
    """
    Deterministic JSON -> SHA256 used for features hashing (must match utils.compute_features_hash).
    """
    canon = json.dumps(features, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()

def verify_block_features(chain: list, index: int) -> Dict[str, Any]:
    """
    Verify a single block's features_hash by finding the original features in features_store and recomputing.
    Returns detailed result dictionary.
    """
    if index < 0 or index >= len(chain):
        return {"ok": False, "reason": "index out of range", "index": index}
    block = chain[index]
    event = block.get("event", {})
    fh = event.get("features_hash") or event.get("featuresHash") or event.get("features")
    if not fh:
        return {"ok": False, "reason": "block does not contain features_hash", "index": index}

    try:
        features = find_feature_row_by_hash(fh)
    except FileNotFoundError as e:
        return {"ok": False, "reason": str(e)}

    if features is None:
        return {"ok": False, "reason": "features not found in features_store", "features_hash": fh}

    recomputed = compute_features_hash(features)
    match = recomputed == fh
    return {"ok": match, "features_hash": fh, "recomputed": recomputed, "index": index}

def main():
    parser = argparse.ArgumentParser(description="Offline blockchain verifier")
    parser.add_argument("--chain", "-c", default=str(CHAIN_JSON), help="Path to chain.json")
    parser.add_argument("--blockchain-py", "-b", default=str(BLOCKCHAIN_PY), help="Path to blockchain.py to import")
    parser.add_argument("--report", "-r", help="Write a verification report JSON to this path")
    parser.add_argument("--verify-block", "-v", type=int, help="Also verify features for the given block index (requires features_store.csv.gz)")
    args = parser.parse_args()

    chain_path = Path(args.chain)
    if not chain_path.exists():
        print(f"ERROR: chain file not found at {chain_path}", file=sys.stderr)
        sys.exit(2)

    # load chain json
    with chain_path.open("r", encoding="utf-8") as f:
        chain = json.load(f)

    # 1) quick link-check verification (prev_hash & recomputed hash)
    print("Verifying chain links and hashes...")
    result = verify_chain(chain)
    print(json.dumps(result, indent=2))
    report = {"chain_file": str(chain_path.resolve()), "verify_result": result}

    # 2) optionally verify block features via features store
    if args.verify_block is not None:
        idx = args.verify_block
        print(f"\nVerifying features hash for block index {idx} (requires {FEATURE_STORE_GZ}) ...")
        try:
            bf_res = verify_block_features(chain, idx)
            print(json.dumps(bf_res, indent=2))
            report["block_features_verification"] = bf_res
        except Exception as e:
            print("Error during block feature verification:", str(e))
            report["block_features_verification"] = {"ok": False, "error": str(e)}

    # 3) optionally write report
    if args.report:
        out = Path(args.report)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nWrote verification report to: {out}")

    # 4) If invalid, print human-friendly remediation hints
    if not result.get("valid", False):
        print("\n=== ATTENTION: Chain verification FAILED ===")
        idx = result.get("broken_at_index")
        reason = result.get("reason")
        print(f"Broken at index: {idx}, reason: {reason}")
        details = result.get("details")
        if details:
            print("Details:", json.dumps(details, indent=2))
        print("\nSuggested next steps:")
        print(" - Do not modify chain.json further.")
        print(" - If you have a backup chain.json, compare blocks up to (index-1).")
        print(" - If only a single block is compromised, you can provide the original features (features_store.csv.gz) for that block to show tampering.")
    else:
        print("\nChain verification OK: chain is intact.")

if __name__ == "__main__":
    main()
