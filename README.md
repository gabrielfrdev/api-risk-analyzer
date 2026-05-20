# api-risk-analyzer

A Python CLI that checks API endpoint metadata and OpenAPI 3.0+ specs against a handful of common OWASP API Security risks — missing auth, IDOR-prone routes, unprotected webhooks, that kind of thing.

It doesn't touch a running API. It reads either a plain JSON list of endpoints or an OpenAPI schema and checks whether security controls were *declared* (`auth_required`, `object_authorization`, `x-rate-limit`, ...). Think schema linter for a CI gate, not a DAST/SAST scanner — it won't catch a bug in your auth middleware, only tell you the route never said it needed one.

## Rules

| Rule | Severity | Flags |
|---|---|---|
| `AUTH-001` | high | Non-public endpoint with no declared auth |
| `API1-001` | critical | Path has an object id (`{id}`, `:user_id`, `{uuid}`) with no `object_authorization` |
| `API5-001` | critical | `/admin` route with no `role_required` |
| `WEBHOOK-001` | high | Webhook route with no `signature_required` |
| `AUTH-002` | high | Login route with no `rate_limit` |
| `DATA-001` | medium | Response schema exposes a sensitive field (token, password, cpf, ...) |

## Install

```bash
pip install .          # or pip install -e . for development
```

## Usage

```bash
api-risk-analyzer --input examples/sample_api.json
api-risk-analyzer --input examples/openapi_sample.json --format markdown --output reports/summary.md
api-risk-analyzer --input examples/openapi_sample.json --format sarif --output reports/results.sarif
api-risk-analyzer --input examples/sample_api.json --fail-on high   # non-zero exit on high/critical findings
```

`--input` is required. `--format` is `json` (default), `markdown`, or `sarif`. `--output` defaults to `reports/generated-report.<ext>`. `--fail-on` takes `low`/`medium`/`high`/`critical`.

## OpenAPI extensions

Global and operation-level `security` blocks are read automatically to infer `auth_required`. For the checks that don't map to standard OpenAPI fields, add these on a path item or operation:

- `x-object-authorization: true`
- `x-role-required: "admin"`
- `x-rate-limit: true`
- `x-signature-required: true`
- `x-response-sensitive-fields: ["token", "password"]`

## Testing

```bash
python -m unittest discover -s tests
```

## License

MIT — see [LICENSE](LICENSE).
