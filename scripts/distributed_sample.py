import json
from pathlib import Path

source = Path.home() / "Downloads/firmable_dataset"
output = Path("distributed_sample.jsonl")

size = source.stat().st_size
valid = 0

with source.open("rb") as src, output.open("wb") as dst:
    for i in range(250):
        offset = int((i + 0.5) / 250 * size)
        src.seek(offset)
        src.readline()  # Skip the partial line

        for _ in range(8):
            line = src.readline()
            if not line:
                break
            try:
                json.loads(line)
                dst.write(line)
                valid += 1
            except (ValueError, UnicodeDecodeError):
                pass

print(f"Sampled {valid} valid records into {output}")
