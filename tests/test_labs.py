import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


linux = load("linux", "01-linux-security-basics/permission_check.py")
nmap = load("nmap", "02-network-enumeration-analysis/app.py")
logs = load("logs", "04-log-analysis/app.py")
verify = load("verify", "05-osint-source-verification/app.py")
metadata = load("metadata", "07-file-metadata-analysis/app.py")


class Tests(unittest.TestCase):
    def test_permission_check(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.txt"
            p.write_text("x")
            p.chmod(0o666)
            self.assertTrue(linux.inspect_path(Path(td)))

    def test_nmap(self):
        hosts = nmap.parse_nmap_xml(ROOT / "sample-data/nmap_sample.xml")
        self.assertEqual([p["port"] for p in hosts[0]["ports"]], [22, 80])

    def test_logs(self):
        out = logs.analyze_log(ROOT / "sample-data/auth.log")
        self.assertEqual(out["ips"]["203.0.113.10"], 3)

    def test_source(self):
        data = json.loads((ROOT / "sample-data/source_record.json").read_text())
        self.assertTrue(all(verify.review(data).values()))

    def test_metadata(self):
        out = metadata.inspect_file(ROOT / "sample-data/sample.txt")
        self.assertEqual(out["mime"], "text/plain")
        self.assertEqual(len(out["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
