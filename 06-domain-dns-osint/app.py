import argparse
import socket


def lookup(domain: str) -> list[dict]:
    results = []
    seen = set()
    for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM):
        address = sockaddr[0]
        key = (family, address)
        if key in seen:
            continue
        seen.add(key)
        results.append({
            "type": "AAAA" if family == socket.AF_INET6 else "A",
            "address": address,
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve public IP addresses for a domain.")
    parser.add_argument("domain")
    args = parser.parse_args()
    try:
        results = lookup(args.domain.strip())
    except socket.gaierror as exc:
        raise SystemExit(f"DNS lookup failed: {exc}")
    for item in results:
        print(f"{item['type']}: {item['address']}")


if __name__ == "__main__":
    main()
