import json
from api_risk_analyzer.openapi import parse_openapi


def load_api(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        raise ValueError(f"input file not found: {path}") from None
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid json: {error}") from error

    if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
        return parse_openapi(data)

    if not isinstance(data, list):
        raise ValueError("Input must be a JSON array of endpoints, or an OpenAPI dictionary.")

    validate_endpoints(data)
    return data


def validate_endpoints(endpoints):
    if not isinstance(endpoints, list):
        raise ValueError("input must be a list of endpoints")

    for index, endpoint in enumerate(endpoints, start=1):
        if not isinstance(endpoint, dict):
            raise ValueError(f"endpoint #{index} must be an object")
        if not endpoint.get("method"):
            raise ValueError(f"endpoint #{index} is missing method")
        if not endpoint.get("path"):
            raise ValueError(f"endpoint #{index} is missing path")
