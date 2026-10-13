import subprocess
import json
import shutil
from typing import List, Dict

class NmapScanner:
    def __init__(self, target: str):
        self.target = target

    def scan(self) -> List[Dict]:
        if not shutil.which("nmap"):
            raise RuntimeError("nmap is not installed or not in PATH")
        cmd = [
            "nmap", "-sV", "--version-all", "-oX", "-", self.target
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"nmap failed: {proc.stderr.strip()}")
        return self._parse_xml(proc.stdout)

    def _parse_xml(self, xml_text: str) -> List[Dict]:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_text)
        findings = []
        for host in root.findall("host"):
            addr = host.find("address").get("addr")
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                findings.append({
                    "host": addr,
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                    "cpe": (service.findtext("cpe") or "") if service is not None else "",
                })
        return findings
