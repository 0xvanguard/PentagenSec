import json
from pathlib import Path
from datetime import datetime, timezone

class CustodyLogger:
    """AU-9 Chain of Custody en JSONL append-only"""
    def __init__(self, output_dir: str):
        self.path = Path(output_dir) / "chain_of_custody.jsonl"
        self.path.parent.mkdir(exist_ok=True, parents=True)
    
    def log(self, action: str, **kwargs):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            **kwargs
        }
        with open(self.path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
