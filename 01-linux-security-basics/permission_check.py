from pathlib import Path
import argparse
import stat


def inspect_path(root: Path) -> list[dict]:
    findings = []
    for path in root.rglob("*"):
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if path.is_file() and (mode & stat.S_IWOTH):
            findings.append({"path": str(path), "issue": "world-writable"})
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Find world-writable files in an authorized directory.")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    target = args.path.expanduser().resolve()
    if not target.exists():
        raise SystemExit(f"Path not found: {target}")
    findings = inspect_path(target)
    if not findings:
        print("No world-writable files found.")
        return
    for item in findings:
        print(f"{item['issue']}: {item['path']}")


if __name__ == "__main__":
    main()
