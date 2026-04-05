"""HTTP-based reconnaissance & web vulnerability probing."""

from __future__ import annotations

import json

import requests
from langchain_core.tools import tool

from src.guardrails import validate_target
from src.logging import get_audit_logger


@tool
def http_get(url: str, follow_redirects: bool = True, timeout: int = 10) -> str:
    """Send an HTTP GET request and return response metadata + body preview.

    Args:
        url: Full URL to request.
        follow_redirects: Whether to follow HTTP redirects.
        timeout: Request timeout in seconds.

    Returns:
        JSON with status code, headers, and truncated body.
    """
    # Extract host from URL for validation
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.hostname:
        validate_target(parsed.hostname)

    audit = get_audit_logger()
    audit.record("http_get_start", tool="http", target=url)

    try:
        resp = requests.get(url, allow_redirects=follow_redirects, timeout=timeout)
        result = {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_preview": resp.text[:2000],
            "content_length": len(resp.content),
            "url": str(resp.url),
        }
        audit.record("http_get_complete", tool="http", target=url, result=f"HTTP {resp.status_code}")
        return json.dumps(result, indent=2)
    except requests.RequestException as exc:
        audit.record("http_get_error", tool="http", target=url, result=str(exc))
        return json.dumps({"error": str(exc)})


@tool
def http_post(url: str, data: dict | None = None, json_body: dict | None = None, timeout: int = 10) -> str:
    """Send an HTTP POST request.

    Args:
        url: Full URL to request.
        data: Form data to send.
        json_body: JSON body to send.
        timeout: Request timeout in seconds.

    Returns:
        JSON with status code, headers, and truncated body.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.hostname:
        validate_target(parsed.hostname)

    audit = get_audit_logger()
    audit.record("http_post_start", tool="http", target=url, parameters={"data": data, "json": json_body})

    try:
        resp = requests.post(url, data=data, json=json_body, timeout=timeout)
        result = {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_preview": resp.text[:2000],
        }
        audit.record("http_post_complete", tool="http", target=url, result=f"HTTP {resp.status_code}")
        return json.dumps(result, indent=2)
    except requests.RequestException as exc:
        audit.record("http_post_error", tool="http", target=url, result=str(exc))
        return json.dumps({"error": str(exc)})


@tool
def directory_bruteforce(base_url: str, wordlist: list[str] | None = None) -> str:
    """Probe common web paths to discover hidden endpoints.

    Args:
        base_url: Base URL (e.g. 'http://172.20.0.3:80').
        wordlist: Custom list of paths to try. Uses defaults if not provided.

    Returns:
        JSON with discovered paths and their status codes.
    """
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    if parsed.hostname:
        validate_target(parsed.hostname)

    audit = get_audit_logger()

    default_paths = [
        "/", "/admin", "/login", "/dashboard", "/api", "/api/v1",
        "/robots.txt", "/.env", "/wp-admin", "/phpmyadmin",
        "/console", "/debug", "/status", "/health", "/info",
        "/server-status", "/server-info", "/.git/HEAD",
        "/backup", "/config", "/shell", "/cmd", "/exec",
    ]
    paths = wordlist or default_paths

    audit.record(
        "dir_bruteforce_start",
        tool="http",
        target=base_url,
        parameters={"paths_count": len(paths)},
    )

    found = []
    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code < 404:
                found.append({
                    "path": path,
                    "status": resp.status_code,
                    "content_length": len(resp.content),
                    "server": resp.headers.get("Server", ""),
                })
        except requests.RequestException:
            continue

    audit.record(
        "dir_bruteforce_complete",
        tool="http",
        target=base_url,
        result=f"Found {len(found)} accessible path(s)",
    )
    return json.dumps(found, indent=2)
