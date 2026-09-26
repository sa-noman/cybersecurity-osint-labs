from pathlib import Path
import argparse
import re
from collections import Counter

PATTERN = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")


def analyze_log(path: Path) -> dict:
    ip_counts, user_counts = Counter(), Counter()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = PATTERN.search(line)
        if m:
            ip_counts[m.group("ip")] += 1
            user_counts[m.group("user")] += 1
    return {"ips": ip_counts, "users": user_counts}


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize failed SSH-style login attempts.")
    parser.add_argument("logfile", type=Path)
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args()
    if not args.logfile.exists():
        raise SystemExit("Log file not found.")
    result = analyze_log(args.logfile)
    print("Failed attempts by IP:")
    for ip, count in result["ips"].most_common():
        marker = " <-- review" if count >= args.threshold else ""
        print(f"{ip}: {count}{marker}")
    print("\nFailed attempts by username:")
    for user, count in result["users"].most_common():
        print(f"{user}: {count}")


if __name__ == "__main__":
    main()
