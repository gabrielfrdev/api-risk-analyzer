def parse_openapi(data):
    endpoints = []

    has_global_security = "security" in data and len(data["security"]) > 0

    paths = data.get("paths", {})
    for route, methods in paths.items():
        for method, details in methods.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                continue

            route_security = details.get("security")
            if route_security is not None:
                auth_required = len(route_security) > 0
            else:
                auth_required = has_global_security

            endpoint = {
                "method": method.upper(),
                "path": route,
                "auth_required": auth_required,
                "public": not auth_required,
                "object_authorization": False,
                "role_required": None,
                "rate_limit": False,
                "signature_required": False,
                "response_sensitive_fields": [],
            }
            endpoints.append(endpoint)

    return endpoints
