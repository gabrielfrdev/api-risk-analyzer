HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


def _extension_value(path_details, operation_details, name, default=None):
    if name in operation_details:
        return operation_details[name]
    if name in path_details:
        return path_details[name]
    return default


def _boolean_extension(path_details, operation_details, name, default=False):
    value = _extension_value(path_details, operation_details, name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _string_extension(path_details, operation_details, name):
    value = _extension_value(path_details, operation_details, name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    value = value.strip()
    return value or None


def _string_list_extension(path_details, operation_details, name):
    value = _extension_value(path_details, operation_details, name, [])
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must contain strings")
    return [item.strip() for item in value if item.strip()]


def _requires_auth(security):
    if not security:
        return False
    return all(bool(requirement) for requirement in security)


def parse_openapi(data):
    endpoints = []

    has_global_security = _requires_auth(data.get("security"))

    paths = data.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI 'paths' must be an object")

    for route, path_details in paths.items():
        if not isinstance(path_details, dict):
            raise ValueError(f"OpenAPI path '{route}' must be an object")

        for method, operation_details in path_details.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation_details, dict):
                continue

            route_security = operation_details.get("security")
            if route_security is not None:
                auth_required = _requires_auth(route_security)
            else:
                auth_required = has_global_security

            endpoint = {
                "method": method.upper(),
                "path": route,
                "auth_required": auth_required,
                "public": not auth_required,
                "object_authorization": _boolean_extension(
                    path_details,
                    operation_details,
                    "x-object-authorization",
                ),
                "role_required": _string_extension(
                    path_details,
                    operation_details,
                    "x-role-required",
                ),
                "rate_limit": _boolean_extension(
                    path_details,
                    operation_details,
                    "x-rate-limit",
                ),
                "signature_required": _boolean_extension(
                    path_details,
                    operation_details,
                    "x-signature-required",
                ),
                "response_sensitive_fields": _string_list_extension(
                    path_details,
                    operation_details,
                    "x-response-sensitive-fields",
                ),
            }
            endpoints.append(endpoint)

    return endpoints
