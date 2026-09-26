from pathlib import Path
import argparse
import json

FIELDS = ["claim", "source_url", "publisher", "author", "published_at", "archive_url", "corroborating_sources", "notes"]


def review(record: dict) -> dict:
    checks = {}
    for field in FIELDS:
        value = record.get(field)
        checks[field] = len(value) > 0 if isinstance(value, list) else bool(value)
    return checks


def main() -> None:
    parser = argparse.ArgumentParser(description="Review OSINT source metadata for completeness.")
    parser.add_argument("record", type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(args.record.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read record: {exc}")
    checks = review(data)
    for field, present in checks.items():
        print(f"{field}: {'present' if present else 'missing'}")


if __name__ == "__main__":
    main()
