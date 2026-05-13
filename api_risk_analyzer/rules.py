import re

SENSITIVE_FIELDS = {"password", "passwd", "token", "secret", "cpf", "ssn", "card_number", "credit_card"}
OBJECT_ID_PATTERN = re.compile(r"(\{(?:[a-zA-Z0-9_-]+_)?(?:id|uuid)\}|\{(?:[a-zA-Z0-9]+)(?:Id|Uuid)\}|:(?:[a-zA-Z0-9_-]+_)?(?:id|uuid)|:(?:[a-zA-Z0-9]+)(?:Id|Uuid))")


def finding(endpoint, rule_id, description, severity, recommendation, category, evidence=None):
    return {
        "rule_id": rule_id,
        "method": endpoint.get("method", "UNKNOWN"),
        "path": endpoint.get("path", "UNKNOWN"),
        "description": description,
        "severity": severity,
        "recommendation": recommendation,
        "category": category,
        "evidence": evidence,
    }


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


def fields(endpoint):
    values = endpoint.get("response_sensitive_fields", [])
    if values is None:
        return []
    return [str(value).strip() for value in values if str(value).strip()]


def check_missing_authentication(endpoints):
    findings = []
    for endpoint in endpoints:
        if not endpoint.get("auth_required", True) and not is_public(endpoint):
            findings.append(finding(
                endpoint,
                rule_id="AUTH-001",
                description="Endpoint is not marked as public and does not require authentication.",
                severity="high",
                recommendation="Require authentication or mark the endpoint as public when exposure is intentional.",
                category="broken-authentication",
                evidence="auth_required is false and public is false",
            ))
    return findings


def check_missing_object_authorization(endpoints):
    findings = []
    for endpoint in endpoints:
        path = endpoint.get("path", "")
        match = OBJECT_ID_PATTERN.search(path)
        if match and not endpoint.get("object_authorization", False):
            findings.append(finding(
                endpoint,
                rule_id="API1-001",
                description="Object identifier in path without object-level authorization.",
                severity="critical",
                recommendation="Ensure the code verifies if the authenticated user has permission to access this specific object ID.",
                category="broken-object-level-authorization",
                evidence=f"Path contains '{match.group(1)}' but object_authorization is false",
            ))
    return findings


def check_admin_without_role(endpoints):
    findings = []
    for endpoint in endpoints:
        path = endpoint.get("path", "")
        if "/admin" in path and not endpoint.get("role_required"):
            findings.append(finding(
                endpoint,
                rule_id="API5-001",
                description="Administrative route without a required role.",
                severity="critical",
                recommendation="Restrict the route to an explicit admin or operator role.",
                category="broken-function-level-authorization",
                evidence="Path contains '/admin' but no role_required is set",
            ))
    return findings


def check_unsigned_webhook(endpoints):
    findings = []
    for endpoint in endpoints:
        path = endpoint.get("path", "")
        if "webhook" in path.lower() and not endpoint.get("signature_required", False):
            findings.append(finding(
                endpoint,
                rule_id="WEBHOOK-001",
                description="Webhook endpoint without signature verification.",
                severity="high",
                recommendation="Add HMAC signature verification to this webhook to prevent spoofing.",
                category="webhook-integrity",
                evidence="Path contains 'webhook' but signature_required is false",
            ))
    return findings


def check_login_without_rate_limit(endpoints):
    findings = []
    for endpoint in endpoints:
        path = endpoint.get("path", "")
        if "login" in path.lower() and not endpoint.get("rate_limit", False):
            findings.append(finding(
                endpoint,
                rule_id="AUTH-002",
                description="Login endpoint without rate limiting.",
                severity="high",
                recommendation="Apply rate limiting and account lockout controls suitable for the application.",
                category="brute-force-protection",
                evidence="Path contains 'login' but rate_limit is false",
            ))
    return findings


def check_sensitive_fields(endpoints):
    findings = []
    for endpoint in endpoints:
        exposed = [field for field in fields(endpoint) if field.lower() in SENSITIVE_FIELDS]
        if exposed:
            findings.append(finding(
                endpoint,
                rule_id="DATA-001",
                description=f"Endpoint metadata includes sensitive fields: {', '.join(exposed)}.",
                severity="medium",
                recommendation="Remove these fields from responses or document why they are required.",
                category="sensitive-data-exposure",
                evidence=f"Fields found: {', '.join(exposed)}",
            ))
    return findings


def score_endpoint(endpoint):
    severities = [item["severity"] for item in run_rules([endpoint])]
    for severity in ("critical", "high", "medium", "low"):
        if severity in severities:
            return severity
    return "low"
