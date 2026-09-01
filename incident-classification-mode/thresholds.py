from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
from typing import Optional


class _Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class Thresholds:
    # Severity thresholds for error_rate (%)
    error_rate_p1: float = 25.0
    error_rate_p2: float = 10.0
    error_rate_p3: float = 5.0

    # Severity thresholds for latency (ms)
    latency_p1: float = 5000.0
    latency_p2: float = 2000.0
    latency_p3: float = 500.0

    # Affected services count thresholds
    affected_services_p1: int = 5
    affected_services_p2: int = 2

    # Category keyword matching
    category_keywords: dict = field(default_factory=lambda: {
        _Category.INFRA.value: [
            "cpu", "memory", "ram", "disk", "io", "host", "node", "server",
            "vm", "container", "pod", "oom", "out-of-memory", "disk-full",
            "provisioning", "infrastructure",
        ],
        _Category.APP.value: [
            "exception", "error", "crash", "timeout", "500", "502", "503",
            "bug", "deployment", "release", "rollback", "app", "service",
            "handler", "traceback", "nil-pointer",
        ],
        _Category.SECURITY.value: [
            "auth", "unauthorized", "breach", "vulnerability", "cve",
            "exploit", "malware", "phishing", "intrusion", "firewall",
            "ssl", "tls", "certificate", "token-leak", "permission",
        ],
        _Category.NETWORK.value: [
            "dns", "tcp", "udp", "latency", "packet-loss", "route",
            "gateway", "vpn", "cdn", "load-balancer", "connection-refused",
            "timeout", "network", "bandwidth",
        ],
    })

    # Metric name prefixes for category detection
    metric_prefixes: dict = field(default_factory=lambda: {
        _Category.INFRA.value: ["cpu", "memory", "ram", "disk", "fs", "load"],
        _Category.APP.value: ["http", "request", "response", "app", "process"],
        _Category.SECURITY.value: ["auth", "login", "firewall", "waf", "vpn"],
        _Category.NETWORK.value: ["net", "tcp", "udp", "dns", "bandwidth", "latency"],
    })

    # Security keywords that auto-escalate to P1
    security_p1_keywords: list[str] = field(default_factory=lambda: [
        "breach", "intrusion", "exploit", "malware", "data-leak",
        "credential-leak", "unauthorized-access",
    ])

    # Severity confidence boost per category
    category_severity_boost: dict = field(default_factory=lambda: {
        _Category.SECURITY.value: 0.10,
        _Category.INFRA.value: 0.05,
        _Category.NETWORK.value: 0.03,
        _Category.APP.value: 0.00,
    })

    @classmethod
    def load_default(cls) -> "Thresholds":
        return cls()

    @classmethod
    def from_file(cls, path: str) -> "Thresholds":
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text())
        instance = cls()
        for key in [
            "error_rate_p1", "error_rate_p2", "error_rate_p3",
            "latency_p1", "latency_p2", "latency_p3",
            "affected_services_p1", "affected_services_p2",
        ]:
            if key in data:
                setattr(instance, key, data[key])
        for key in ["category_keywords", "metric_prefixes", "category_severity_boost"]:
            if key in data:
                current = getattr(instance, key)
                for k, v in data[key].items():
                    current[k] = v
        for key in ["security_p1_keywords"]:
            if key in data:
                setattr(instance, key, data[key])
        return instance

    def to_dict(self) -> dict:
        return {
            "error_rate_p1": self.error_rate_p1,
            "error_rate_p2": self.error_rate_p2,
            "error_rate_p3": self.error_rate_p3,
            "latency_p1": self.latency_p1,
            "latency_p2": self.latency_p2,
            "latency_p3": self.latency_p3,
            "affected_services_p1": self.affected_services_p1,
            "affected_services_p2": self.affected_services_p2,
            "category_keywords": self.category_keywords,
            "metric_prefixes": self.metric_prefixes,
            "security_p1_keywords": self.security_p1_keywords,
            "category_severity_boost": self.category_severity_boost,
        }