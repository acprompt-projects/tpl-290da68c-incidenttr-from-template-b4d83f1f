from dispatcher import Channel, RoutingRule, Severity, NotificationDispatcher, RateLimiter, SlackNotifier, PagerDutyNotifier, EmailNotifier

DEFAULT_ROUTING_RULES: list[RoutingRule] = [
    RoutingRule(
        channels=[Channel.PAGERDUTY, Channel.SLACK],
        min_severity=Severity.CRITICAL,
    ),
    RoutingRule(
        channels=[Channel.PAGERDUTY, Channel.SLACK],
        min_severity=Severity.HIGH,
        categories=["infra", "database", "security"],
    ),
    RoutingRule(
        channels=[Channel.SLACK],
        min_severity=Severity.HIGH,
    ),
    RoutingRule(
        channels=[Channel.SLACK, Channel.EMAIL],
        min_severity=Severity.MEDIUM,
        categories=["application", "network"],
    ),
    RoutingRule(
        channels=[Channel.EMAIL],
        min_severity=Severity.LOW,
    ),
]


def build_dispatcher(
    slack_webhook_url: str = "",
    pagerduty_routing_key: str = "",
    email_smtp_host: str = "localhost",
    email_smtp_port: int = 25,
    email_sender: str = "incidents@example.com",
    email_recipients: list[str] | None = None,
    rate_limit_max: int = 10,
    rate_limit_window: float = 60.0,
) -> NotificationDispatcher:
    notifiers = {}
    if slack_webhook_url:
        notifiers[Channel.SLACK] = SlackNotifier(slack_webhook_url)
    if pagerduty_routing_key:
        notifiers[Channel.PAGERDUTY] = PagerDutyNotifier(pagerduty_routing_key)
    if email_smtp_host:
        notifiers[Channel.EMAIL] = EmailNotifier(
            smtp_host=email_smtp_host,
            smtp_port=email_smtp_port,
            sender=email_sender,
            recipients=email_recipients or ["oncall@example.com"],
        )
    return NotificationDispatcher(
        routing_rules=DEFAULT_ROUTING_RULES,
        notifiers=notifiers,
        rate_limiter=RateLimiter(max_calls=rate_limit_max, window_seconds=rate_limit_window),
    )