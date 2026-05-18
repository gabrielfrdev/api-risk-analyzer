# api-risk-analyzer

A simple Python CLI tool to analyze API endpoint schemas and metadata for common OWASP API security risks.

It reads custom JSON route definitions or OpenAPI 3.0+ schemas and checks for missing security declarations like unauthenticated endpoints, ID-based routes missing object ownership checks, unprotected webhooks, and exposed sensitive response fields.

## Scope & Limitations

This tool acts as a **static metadata linter** for API specs and design checklists.

It is **not** a DAST (dynamic scanner) or SAST tool:
- It does not send live HTTP requests to endpoints.
- It does not scan underlying backend code (Python/Node/Go).
- It relies on endpoint metadata or OpenAPI extension tags (e.g. `x-object-authorization`, `x-rate-limit`) to verify whether security controls were declared during API design.

## Rules Covered

- **AUTH-001**: Private endpoints missing authentication requirements.
- **API1-001**: Path parameters containing IDs (`{id}`, `{uuid}`, `:user_id`) without declared object authorization logic (BOLA/IDOR risk).
- **API5-001**: Administrative endpoints (`/admin`) missing role restrictions.
- **WEBHOOK-001**: Public webhooks that do not require HMAC signature verification.
- **AUTH-002**: Login routes (`/auth/login`) without rate limiting controls.
- **DATA-001**: Sensitive fields (passwords, tokens, keys) declared in response fields.

## Quickstart

Install locally:

```bash
pip install .
```

Run on a sample JSON file:

```bash
api-risk-analyzer --input examples/sample_api.json
```

Run on an OpenAPI spec and export Markdown:

```bash
python analyzer.py --input examples/openapi_sample.json --format markdown --output reports/summary.md
```

Export SARIF for GitHub Code Scanning:

```bash
api-risk-analyzer --input examples/openapi_sample.json --format sarif --output reports/results.sarif
```

Fail build on high or critical findings:

```bash
api-risk-analyzer --input examples/sample_api.json --fail-on high
```

## OpenAPI Vendor Extensions

For OpenAPI schemas, `api-risk-analyzer` parses global and operation-level `security` fields automatically. You can also specify vendor extensions on path items or operations:

- `x-object-authorization: true`
- `x-role-required: "admin"`
- `x-rate-limit: true`
- `x-signature-required: true`
- `x-response-sensitive-fields: ["token", "password"]`

## Testing

Run tests with `unittest`:

```bash
python -m unittest discover -s tests
```

## License

[MIT License](file:///C:/Users/gabri/Desktop/github/api-risk-analyzer/LICENSE)
