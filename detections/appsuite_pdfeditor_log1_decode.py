
"""
Author: dorkerdevil
Decode LOG1 file from AppSuite PDF Editor backdoor
Based on G DATA's published script
"""
import json
import sys
from pathlib import Path

config_keys = [
    "debug", "fhkey", "cid", "iid", "c-key", "e-key", "usid", "size",
    "ol-key", "wv-key", "sf-key", "cw-key", "ew-key", "pas-key"
]

def decode_log1(file_path):
    p = Path(file_path)
    hex_content = p.read_text().strip()
    decoded_json_str = bytes.fromhex(hex_content).decode("utf-8")
    parsed = json.loads(decoded_json_str) if decoded_json_str else {}
    values = parsed.get("json", [])
    if not isinstance(values, list):
        values = []
    while len(values) < len(config_keys):
        values.append("")
    mapped = dict(zip(config_keys, values))
    return mapped

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <LOG1 file>")
        sys.exit(1)
    log1_file = sys.argv[1]
    try:
        result = decode_log1(log1_file)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
