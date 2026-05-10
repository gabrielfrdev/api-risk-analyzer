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
        method = endpoint.get("method")
        if not method or not isinstance(method, str) or not method.strip():
            raise ValueError(f"endpoint #{index} is missing a valid method")
            
        path = endpoint.get("path")
        if not path or not isinstance(path, str) or not path.strip():
            raise ValueError(f"endpoint #{index} is missing a valid path")
            
        for bool_field in ["auth_required", "public", "object_authorization", "rate_limit", "signature_required"]:
            if bool_field in endpoint and not isinstance(endpoint[bool_field], bool):
                raise ValueError(f"endpoint #{index} field '{bool_field}' must be a boolean")
                
        if "response_sensitive_fields" in endpoint and not isinstance(endpoint["response_sensitive_fields"], list):
            raise ValueError(f"endpoint #{index} field 'response_sensitive_fields' must be a list")
