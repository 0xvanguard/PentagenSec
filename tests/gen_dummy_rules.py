import os
from pathlib import Path
import yaml

def generate_dummy_rules(out_dir: str, num_rules: int):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    for i in range(num_rules):
        rule = {
            "title": f"Dummy Rule {i}",
            "id": f"dummy-rule-{i}",
            "detection": {
                "sel": {
                    "re": f"evil_pattern_{i}[A-Z]+"
                }
            }
        }
        with open(os.path.join(out_dir, f"dummy_{i}.yml"), "w") as f:
            yaml.dump(rule, f)

if __name__ == "__main__":
    import sys
    generate_dummy_rules("rules_test", 100)
    print("Created 100 dummy rules in rules_test/")
