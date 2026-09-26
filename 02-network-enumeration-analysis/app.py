from pathlib import Path
import argparse
from xml.etree import ElementTree as ET


def parse_nmap_xml(path: Path) -> list[dict]:
    root = ET.parse(path).getroot()
    hosts = []
    for host in root.findall("host"):
        addr = host.find("address")
        address = addr.get("addr") if addr is not None else "unknown"
        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else "unknown",
            })
        hosts.append({"address": address, "ports": ports})
    return hosts


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze saved Nmap XML output.")
    parser.add_argument("xml_file", type=Path)
    args = parser.parse_args()
    try:
        hosts = parse_nmap_xml(args.xml_file)
    except (OSError, ET.ParseError) as exc:
        raise SystemExit(f"Could not parse report: {exc}")
    for host in hosts:
        print(f"Host: {host['address']}")
        if not host["ports"]:
            print("  No open ports recorded.")
        for port in host["ports"]:
            print(f"  {port['port']}/{port['protocol']}  {port['service']}")


if __name__ == "__main__":
    main()
