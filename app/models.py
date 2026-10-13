from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

@dataclass
class ServiceFinding:
    host: str
    port: int
    protocol: str
    service: str
    product: str = ""
    version: str = ""
    cpe: str = ""
    cves: List[Dict] = field(default_factory=list)
    kev: bool = False
    epss_score: float = 0.0
    priority: str = "later"
    score: float = 0.0
    ai_summary: str = ""
    ai_fix: str = ""
    ai_cves: List[str] = field(default_factory=list)
    verified: bool = True

    def to_dict(self):
        return asdict(self)
