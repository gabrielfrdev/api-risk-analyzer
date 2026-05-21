import re

SENSITIVE_FIELDS = {
    "access_token",
    "api_key",
    "card_number",
    "client_secret",
    "cpf",
    "credit_card",
    "passwd",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_id",
    "ssn",
    "token",
}

OBJECT_ID_PATTERN = re.compile(
    r"("
    r"\{(?:[a-zA-Z0-9_-]+_)?(?:id|uuid)\}|"
    r"\{(?:[a-zA-Z0-9]+)(?:Id|Uuid)\}|"
    r":(?:[a-zA-Z0-9_-]+_)?(?:id|uuid)|"
    r":(?:[a-zA-Z0-9]+)(?:Id|Uuid)"
    r")"
)


def finding(endpoint, rule_id, description, severity, recommendation, category, evidence=None, endpoint_index=None):
    item = {
        "rule_id": rule_id,
        "method": endpoint.get("method", "UNKNOWN"),
        "path": endpoint.get("path", "UNKNOWN"),
        "description": description,
        "severity": severity,
        "recommendation": recommendation,
        "category": category,
        "evidence": evidence,
    }
    if endpoint_index is not None:
        item["endpoint_index"] = endpoint_index
    return item


def run_rules(endpoints):
    checks = [
        check_missing_authentication,
        check_missing_object_authorization,
        check_admin_without_role,
        check_unsigned_webhook,
        check_login_without_rate_limit,
        check_sensitive_fields,
    ]

    findings = []
    for check in checks:
        findings.extend(check(endpoints))
    return findings


def is_public(endpoint):
    return bool(endpoint.get("public", False))


def _normalize_field_name(value):
    name = str(value).strip()
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    name = re.sub(r"[^a-zA-Z0-9]+", "_", name)
    return name.strip("_").lower()


def is_sensitive_field_name(value):
    return _normalize_field_name(value) in SENSITIVE_FIELDS


def _get_segments(path):
    return [
        segment.lower().replace("-", "_")
        for segment in path.strip("/").split("/")
        if segment
    ]


def _has_segment(path, names):
    return bool(set(_get_segments(path)) & set(names))


def fields(endpoint):
    values = endpoint.get("response_sensitive_fields", [])
    if values is None:
        return []
    return [str(value).strip() for value in values if str(value).strip()]


def check_missing_authentication(endpoints):
    findings = []
    for index, endpoint in enumerate(endpoints):
        if not endpoint.get("auth_required", True) and not is_public(endpoint):
            findings.append(finding(
                endpoint,
                rule_id="AUTH-001",
                description="Endpoint is not marked as public and does not require authentication.",
                severity="high",
                recommendation=(
                    "Require authentication or mark the endpoint as public "
                    "when exposure is intentional."
                ),
                category="broken-authentication",
                evidence="auth_required is false and public is false",
                endpoint_index=index,
            ))
    return findings


def check_missing_object_authorization(endpoints):
    findings = []
    for index, endpoint in enumerate(endpoints):
        path = endpoint.get("path", "")
        match = OBJECT_ID_PATTERN.search(path)
        if match and not endpoint.get("object_authorization", False):
            findings.append(finding(
                endpoint,
                rule_id="API1-001",
                description="Object identifier in path without object-level authorization.",
                severity="critical",
                recommendation=(
                    "Ensure the code verifies if the authenticated user has "
                    "permission to access this specific object ID."
                ),
                category="broken-object-level-authorization",
                evidence=f"Path contains '{match.group(1)}' but object_authorization is false",
                endpoint_index=index,
            ))
    return findings


def check_admin_without_role(endpoints):
    findings = []
    for index, endpoint in enumerate(endpoints):
        path = endpoint.get("path", "")
        if _has_segment(path, {"admin", "admins"}) and not endpoint.get("role_required"):
            findings.append(finding(
                endpoint,
                rule_id="API5-001",
                description="Administrative route without a required role.",
                severity="critical",
                recommendation="Restrict the route to an explicit admin or operator role.",
                category="broken-function-level-authorization",
                evidence="Path contains '/admin' but no role_required is set",
                endpoint_index=index,
            ))
    return findings


def check_unsigned_webhook(endpoints):
    findings = []
    for index, endpoint in enumerate(endpoints):
        path = endpoint.get("path", "")
        if (
            _has_segment(path, {"webhook", "webhooks"})
            and not endpoint.get("signature_required", False)
        ):
            findings.append(finding(
                endpoint,
                rule_id="WEBHOOK-001",
                description="Webhook endpoint without signature verification.",
                severity="high",
                recommendation=(
                    "Add HMAC signature verification to this webhook "
                    "to prevent spoofing."
                ),
                category="webhook-integrity",
                evidence="Path contains 'webhook' but signature_required is false",
                endpoint_index=index,
            ))
    return findings


def check_login_without_rate_limit(endpoints):
    findings = []
    for index, endpoint in enumerate(endpoints):
        path = endpoint.get("path", "")
        login_segments = {"login", "logins", "sign_in", "signin"}
        if _has_segment(path, login_segments) and not endpoint.get("rate_limit", False):
            findings.append(finding(
                endpoint,
                rule_id="AUTH-002",
                description="Login endpoint without rate limiting.",
                severity="high",
                recommendation=(
                    "Apply rate limiting and account lockout controls "
                    "suitable for the application."
                ),
                category="brute-force-protection",
                evidence="Path contains 'login' but rate_limit is false",
                endpoint_index=index,
            ))
    return findings


def check_sensitive_fields(endpoints):
    findings = []
    for index, endpoint in enumerate(endpoints):
        exposed = [field for field in fields(endpoint) if is_sensitive_field_name(field)]
        if exposed:
            findings.append(finding(
                endpoint,
                rule_id="DATA-001",
                description=f"Endpoint metadata includes sensitive fields: {', '.join(exposed)}.",
                severity="medium",
                recommendation=(
                    "Remove these fields from responses or document why "
                    "they are required."
                ),
                category="sensitive-data-exposure",
                evidence=f"Fields found: {', '.join(exposed)}",
                endpoint_index=index,
            ))
    return findings


def score_endpoint(endpoint, endpoint_findings=None):
    if endpoint_findings is None:
        endpoint_findings = run_rules([endpoint])
    severities = [item["severity"] for item in endpoint_findings]
    for severity in ("critical", "high", "medium", "low"):
        if severity in severities:
            return severity
    return "low"

