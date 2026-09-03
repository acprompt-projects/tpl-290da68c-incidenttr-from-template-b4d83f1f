from models import IncidentSubmit, Severity

_KEYWORD_RULES: dict[Severity, list[str]] = {
    Severity.critical: ["out of memory", "datacenter down", "cluster unreachable"],
    Severity.high: ["high latency", "error rate spike", "replica failure"],
    Severity.medium: ["disk usage high", "cpu throttling", "queue backlog"],
    Severity.low: ["slow query", "retry succeeded", "degraded replica"],
}

def classify_incident(incident: IncidentSubmit) -> Severity:
    text = f"{incident.title} {incident.description}".lower()
    tags = {k.lower(): v.lower() for k, v in incident.source.tags.items()}
    if tags.get("severity") in [s.value for s in Severity]:
        return Severity(tags["severity"])
    for sev, keywords in _KEYWORD_RULES.items():
        if any(kw in text for kw in keywords):
            return sev
    if "critical" in tags.get("priority", ""):
        return Severity.critical
    return Severity.medium