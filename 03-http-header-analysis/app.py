import argparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def analyze(url: str, timeout: float = 10.0) -> dict:
    req = Request(url, headers={"User-Agent": "defensive-security-lab/1.0"})
    with urlopen(req, timeout=timeout) as response:
        final_url = response.geturl()
        return {
            "status": response.status,
            "final_url": final_url,
            "https": urlparse(final_url).scheme == "https",
            "headers": {h: response.headers.get(h) for h in SECURITY_HEADERS},
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect common HTTP security headers.")
    parser.add_argument("url")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    try:
        result = analyze(args.url, args.timeout)
    except (URLError, HTTPError, ValueError) as exc:
        raise SystemExit(f"Request failed: {exc}")
    print(f"Status: {result['status']}")
    print(f"Final URL: {result['final_url']}")
    print(f"HTTPS: {'yes' if result['https'] else 'no'}")
    for name, value in result["headers"].items():
        print(f"{name}: {value or 'MISSING'}")


if __name__ == "__main__":
    main()
