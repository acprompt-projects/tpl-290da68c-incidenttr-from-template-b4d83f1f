import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from thresholds import Thresholds


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass(frozen=True)
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    reason: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": round(self.confidence, 2),
            "reason": self.reason,
        }


@dataclass
class Incident:
    title: str
    description: str
    source: str
    tags: list[str]
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    affected_services: Optional[list[str]] = None
    error_rate: Optional[float] = None
    latency_ms: Optional[float] = None


class IncidentClassifier:
    def __init__(self, thresholds: Optional[Thresholds] = None):
        self.thresholds = thresholds or Thresholds.load_default()

    def classify(self, incident: Incident) -> TriageLabel:
        category, cat_conf, cat_reason = self._classify_category(incident)
        severity, sev_conf, sev_reason = self._classify_severity(incident, category)
        confidence = round((cat_conf + sev_conf) / 2, 3)
        reason = f"{cat_reason}; {sev_reason}"
        return TriageLabel(severity=severity, category=category, confidence=confidence, reason=reason)

    def _classify_category(self, incident: Incident) -> tuple[Category, float, str]:
        text = f"{incident.title} {incident.description} {' '.join(incident.tags)}".lower()
        scores: dict[Category, float] = {c: 0.0 for c in Category}
        reasons: dict[Category, list[str]] = {c: [] for c in Category}

        for category, keywords in self.thresholds.category_keywords.items():
            for kw in keywords:
                pattern = re.compile(rf"\b{re.escape(kw)}\b")
                if pattern.search(text):
                    scores[category] += 1.0
                    reasons[category].append(f"keyword:{kw}")
            for tag in incident.tags:
                if tag.lower() in [k.lower() for k in keywords]:
                    scores[category] += 0.5

        if incident.metric_name:
            metric_lower = incident.metric_name.lower()
            for category, prefixes in self.thresholds.metric_prefixes.items():
                if any(metric_lower.startswith(p) for p in prefixes):
                    scores[category] += 1.5
                    reasons[category].append(f"metric:{incident.metric_name}")

        if not any(scores.values()):
            scores[Category.APP] = 1.0
            reasons[Category.APP].append("default_fallback")

        best_cat = max(Category, key=lambda c: scores[c])
        total = sum(scores.values()) or 1.0
        confidence = min(scores[best_cat] / total, 1.0) if scores[best_cat] > 0 else 0.25
        reason = f"category={best_cat.value} matched [{', '.join(reasons[best_cat])}]"
        return best_cat, confidence, reason

    def _classify_severity(self, incident: Incident, category: Category) -> tuple[Severity, float, str]:
        t = self.thresholds
        signals: list[tuple[Severity, float, str]] = []

        if incident.error_rate is not None:
            if incident.error_rate >= t.error_rate_p1:
                signals.append((Severity.P1, 0.95, f"error_rate={incident.error_rate}%>=p1"))
            elif incident.error_rate >= t.error_rate_p2:
                signals.append((Severity.P2, 0.85, f"error_rate={incident.error_rate}%>=p2"))
            elif incident.error_rate >= t.error_rate_p3:
                signals.append((Severity.P3, 0.70, f"error_rate={incident.error_rate}%>=p3"))
            else:
                signals.append((Severity.P4, 0.50, f"error_rate={incident.error_rate}%<p3"))

        if incident.latency_ms is not None:
            if incident.latency_ms >= t.latency_p1:
                signals.append((Severity.P1, 0.90, f"latency={incident.latency_ms}ms>=p1"))
            elif incident.latency_ms >= t.latency_p2:
                signals.append((Severity.P2, 0.80, f"latency={incident.latency_ms}ms>=p2"))
            elif incident.latency_ms >= t.latency_p3:
                signals.append((Severity.P3, 0.65, f"latency={incident.latency_ms}ms>=p3"))
            else:
                signals.append((Severity.P4, 0.45, f"latency={incident.latency_ms}ms<p3"))

        if category == Category.SECURITY:
            text = f"{incident.title} {incident.description}".lower()
            for kw in t.security_p1_keywords:
                if kw in text:
                    signals.append((Severity.P1, 0.95, f"security_critical:{kw}"))
                    break
            else:
                signals.append((Severity.P2, 0.75, "security_default_elevated"))

        sev_boost = t.category_severity_boost.get(category, 0.0)
        affected_count = len(incident.affected_services) if incident.affected_services else 0
        if affected_count >= t.affected_services_p1:
            signals.append((Severity.P1, 0.90, f"affected_services={affected_count}>=p1"))
        elif affected_count >= t.affected_services_p2:
            signals.append((Severity.P2, 0.80, f"affected_services={affected_count}>=p2"))

        if not signals:
            return Severity.P4, 0.30, "no_signals_default_p4"

        worst = max(signals, key=lambda s: s[0].value)
        sev = worst[0]
        conf = min(worst[1] + sev_boost, 1.0)
        reason_parts = [s[2] for s in signals]
        if sev_boost > 0:
            reason_parts.append(f"boost=+{sev_boost}")
        return sev, conf, f"severity={sev.value} [{', '.join(reason_parts)}]"