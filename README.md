# API Risk Analyzer

Small Python script for checking API route metadata.

It reads a JSON file or an OpenAPI schema and reports risky defaults, like missing auth, ID-based routes without object checks, public webhooks without signatures, login routes without rate limits, and sensitive fields in responses.

## Run

```bash
python analyzer.py --input examples/sample_api.json
```

Markdown output:
```bash
python analyzer.py --input examples/sample_api.json --format markdown --output reports/generated-report.md
```

Fail on high severity findings:
```bash
python analyzer.py --input examples/sample_api.json --fail-on high
```
