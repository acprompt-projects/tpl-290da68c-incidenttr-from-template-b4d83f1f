import time
import logging
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

import httpx

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class Channel(Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


@dataclass
class Incident:
    id: str
    severity: Severity
    category: str
    title: str
    description: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class RoutingRule:
    channels: list[Channel]
    min_severity: Severity = Severity.INFO
    categories: list[str] = field(default_factory=list)

    def matches(self, incident: Incident) -> bool:
        if incident.severity.value < self.min_severity.value:
            return False
        if self.categories and incident.category not in self.categories:
            return False
        return True


class RateLimiter:
    def __init__(self, max_calls: int = 10, window_seconds: float = 60.0):
        self.max_calls = max_calls
        self.window = window_seconds
        self._timestamps: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        timestamps = self._timestamps[key]
        cutoff = now - self.window
        self._timestamps[key] = [t for t in timestamps if t > cutoff]
        if len(self._timestamps[key]) >= self.max_calls:
            return False
        self._timestamps[key].append(now)
        return True


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self._client = httpx.Client(timeout=10.0)

    def send(self, incident: Incident) -> bool:
        severity_colors = {
            Severity.CRITICAL: "#ff0000", Severity.HIGH: "#ff6600",
            Severity.MEDIUM: "#ffcc00", Severity.LOW: "#36a64f", Severity.INFO: "#808080",
        }
        payload = {
            "attachments": [{
                "color": severity_colors.get(incident.severity, "#808080"),
                "title": f"[{incident.severity.name}] {incident.title}",
                "text": incident.description,
                "fields": [
                    {"title": "Category", "value": incident.category, "short": True},
                    {"title": "Incident ID", "value": incident.id, "short": True},
                ],
                "footer": "Incident Triage Service",
            }]
        }
        try:
            resp = self._client.post(self.webhook_url, json=payload)
            resp.raise_for_status()
            logger.info("Slack notification sent for incident %s", incident.id)
            return True
        except httpx.HTTPError as exc:
            logger.error("Slack notification failed for %s: %s", incident.id, exc)
            return False


class PagerDutyNotifier:
    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        self.routing_key = routing_key
        self.api_url = api_url
        self._client = httpx.Client(timeout=10.0)

    def send(self, incident: Incident) -> bool:
        severity_map = {
            Severity.CRITICAL: "critical", Severity.HIGH: "high",
            Severity.MEDIUM: "warning", Severity.LOW: "info", Severity.INFO: "info",
        }
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": incident.title,
                "severity": severity_map.get(incident.severity, "info"),
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category,
                "group": incident.id,
                "custom_details": {"description": incident.description},
            },
        }
        try:
            resp = self._client.post(self.api_url, json=payload)
            resp.raise_for_status()
            logger.info("PagerDuty notification sent for incident %s", incident.id)
            return True
        except httpx.HTTPError as exc:
            logger.error("PagerDuty notification failed for %s: %s", incident.id, exc)
            return False


class EmailNotifier:
    def __init__(self, smtp_host: str, smtp_port: int, sender: str, recipients: list[str]):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients

    def send(self, incident: Incident) -> bool:
        import smtplib
        from email.mime.text import MIMEText
        subject = f"[{incident.severity.name}] {incident.title} ({incident.category})"
        body = f"Incident ID: {incident.id}\nSeverity: {incident.severity.name}\nCategory: {incident.category}\n\n{incident.description}"
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.sendmail(self.sender, self.recipients, msg.as_string())
            logger.info("Email notification sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("Email notification failed for %s: %s", incident.id, exc)
            return False


class NotificationDispatcher:
    def __init__(
        self,
        routing_rules: list[RoutingRule],
        notifiers: dict[Channel, object],
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.routing_rules = routing_rules
        self.notifiers = notifiers
        self.rate_limiter = rate_limiter or RateLimiter()

    def resolve_channels(self, incident: Incident) -> list[Channel]:
        matched: set[Channel] = set()
        for rule in self.routing_rules:
            if rule.matches(incident):
                matched.update(rule.channels)
        return list(matched)

    def dispatch(self, incident: Incident) -> dict[str, bool]:
        channels = self.resolve_channels(incident)
        results: dict[str, bool] = {}
        for channel in channels:
            rate_key = hashlib.md5(f"{channel.value}:{incident.category}".encode()).hexdigest()
            if not self.rate_limiter.is_allowed(rate_key):
                logger.warning("Rate limited: channel=%s category=%s", channel.value, incident.category)
                results[channel.value] = False
                continue
            notifier = self.notifiers.get(channel)
            if notifier is None:
                logger.error("No notifier configured for channel %s", channel.value)
                results[channel.value] = False
                continue
            results[channel.value] = notifier.send(incident)
        return results