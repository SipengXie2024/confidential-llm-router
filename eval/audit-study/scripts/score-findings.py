#!/usr/bin/env python3
import csv
import sys
from pathlib import Path


STOPWORDS = {
    "a",
    "an",
    "and",
    "back",
    "before",
    "can",
    "does",
    "exact",
    "field",
    "from",
    "gains",
    "host",
    "is",
    "no",
    "or",
    "that",
    "the",
    "to",
    "upstream",
    "with",
}


def load_answer_key(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="") as f:
        return {
            row["seed_id"]: {
                "location": row["expected_location"].lower(),
                "finding": row["expected_finding"].lower(),
            }
            for row in csv.DictReader(f)
        }


def detected(expected: dict[str, str], text: str) -> bool:
    if expected["location"] not in text:
        return False
    if "finding_id:" in text and "no_findings: true" not in text:
        return True
    tokens = [
        tok.strip(".,;:()[]`\"'")
        for tok in expected["finding"].replace("/", " ").replace("-", " ").split()
    ]
    tokens = [tok for tok in tokens if len(tok) >= 4 and tok not in STOPWORDS]
    if not tokens:
        return False
    hits = sum(1 for tok in tokens if tok in text)
    return hits >= min(3, len(tokens))


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: score-findings.py answer-key.csv summary.csv transcript-dir", file=sys.stderr)
        return 2
    answer_key = load_answer_key(Path(sys.argv[1]))
    summary = Path(sys.argv[2])
    transcript_dir = Path(sys.argv[3])

    rows = []
    with summary.open(newline="") as f:
        for row in csv.DictReader(f):
            seed = row["seed_id"]
            auditor = row["auditor"]
            if seed == "clean":
                rows.append(row)
                continue
            expected = answer_key.get(seed)
            transcript_path = transcript_dir / seed / f"{auditor}.md"
            text = transcript_path.read_text(errors="replace").lower() if transcript_path.exists() else ""
            row["detected"] = "true" if expected and detected(expected, text) else "false"
            row["transcript_path"] = str(transcript_path)
            rows.append(row)

    writer = csv.DictWriter(sys.stdout, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
