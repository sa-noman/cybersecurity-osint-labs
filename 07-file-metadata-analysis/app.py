from pathlib import Path
import argparse
import hashlib
import mimetypes
from datetime import datetime, timezone


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def inspect_file(path: Path) -> dict:
    stat = path.stat()
    mime, _ = mimetypes.guess_type(path.name)
    return {
        "name": path.name,
        "size": stat.st_size,
        "mime": mime or "unknown",
        "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "sha256": sha256(path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect basic file metadata and SHA-256.")
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    if not args.file.is_file():
        raise SystemExit("File not found.")
    result = inspect_file(args.file)
    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
