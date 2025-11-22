# blockchain.py (OFFLINE VERSION)
import json, time, hashlib
from pathlib import Path

CHAIN_FILE = Path("chain.json")

class Blockchain:
    def __init__(self):
        if CHAIN_FILE.exists():
            self.chain = json.loads(CHAIN_FILE.read_text())
        else:
            genesis = self._make_block(
                index=0,
                timestamp=time.time(),
                event={"type": "genesis_block"},
                prev_hash="0"*64
            )
            self.chain = [genesis]
            self._save()

    def _save(self):
        CHAIN_FILE.write_text(json.dumps(self.chain, indent=2))

    def _compute_hash(self, block):
        block_copy = {k: block[k] for k in sorted(block) if k != "hash"}
        encoded = json.dumps(block_copy, separators=(',', ':'), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def _make_block(self, index, timestamp, event, prev_hash):
        block = {
            "index": index,
            "timestamp": timestamp,
            "event": event,
            "prev_hash": prev_hash
        }
        block["hash"] = self._compute_hash(block)
        return block

    def create_block(self, event):
        last_block = self.chain[-1]
        block = self._make_block(
            index=last_block["index"] + 1,
            timestamp=time.time(),
            event=event,
            prev_hash=last_block["hash"]
        )
        self.chain.append(block)
        self._save()
        return block

    def verify_chain(self):
        for i in range(1, len(self.chain)):
            prev = self.chain[i-1]
            curr = self.chain[i]
            if curr["prev_hash"] != prev["hash"]:
                return {"valid": False, "broken_at_index": i}
            if self._compute_hash(curr) != curr["hash"]:
                return {"valid": False, "broken_at_index": i}
        return {"valid": True}
