"""
analyzers/cookies.py — Módulo de análise de segurança de cookies.

Faz o parsing dos headers Set-Cookie usando o mecanismo padrão do `http.cookiejar`
(via requests), em vez de usar comparação de strings “na mão”. Isso evita falsos positivos
que acontecem quando se procura nomes de flags dentro de valores de cookies ou atributos como path.

Flags de segurança avaliadas
-----------------------------

  Secure   — garante que o cookie só seja enviado via HTTPS
  HttpOnly — impede acesso ao cookie via JavaScript (mitiga roubo via XSS)
  SameSite — controla envio em requisições cross-site (mitiga ataques CSRF)

Referências
------------

- RFC 6265 § 5.2 (Parsing de Set-Cookie)
- OWASP Testing Guide — OTG-SESS-002
"""

from typing import List
from http_client import HttpResponse
from core.models import Severity, Vulnerability


def _parse_set_cookie_headers(response: HttpResponse) -> List[dict]:

    cookies = []

    if response.raw is None:
        return cookies

    for cookie in response.raw.cookies:

        raw_rest = {k.lower(): v for k, v in (cookie._rest or {}).items()}

        cookies.append({
            "name": cookie.name,
            "secure": bool(cookie.secure),
            "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            "samesite": raw_rest.get("samesite", None),
        })

    if not cookies:
        for raw_header in _raw_set_cookie_values(response):
            cookies.append(_parse_single_set_cookie(raw_header))

    return cookies


def _raw_set_cookie_values(response: HttpResponse) -> List[str]:

    values = []
    if response.raw and hasattr(response.raw, "raw") and hasattr(response.raw.raw, "headers"):

        try:
            values = response.raw.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            pass
    if not values:

        raw = response.headers.get("Set-Cookie", "")
        if raw:
            values = [raw]
    return values


def _parse_single_set_cookie(header_value: str) -> dict:

    parts = [p.strip() for p in header_value.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else "unknown"

    attrs_lower = [p.lower() for p in parts[1:]]  # skip name=value

    samesite = None
    for attr in parts[1:]:
        if attr.strip().lower().startswith("samesite"):
            samesite = attr.split("=", 1)[-1].strip() if "=" in attr else "present"
            break

    return {
        "name": name,
        "secure": "secure" in attrs_lower,
        "httponly": "httponly" in attrs_lower,
        "samesite": samesite,
    }


def analyze(response: HttpResponse) -> List[Vulnerability]:

    findings: List[Vulnerability] = []
    cookies = _parse_set_cookie_headers(response)

    for cookie in cookies:
        name = cookie["name"]

        # --- Secure flag ---
        if not cookie["secure"]:
            findings.append(
                Vulnerability(
                    title=f"Cookie sem flag Secure: {name}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The cookie '{name}' is missing the Secure attribute.  "
                        "Without it the browser may transmit the cookie over an "
                        "unencrypted HTTP connection, exposing it to network sniffing."
                    ),
                    evidence=f"Set-Cookie: {name}=...; [Secure flag absent]",
                    recommendation=f"Add the Secure flag: Set-Cookie: {name}=...; Secure; ...",
                )
            )

        # --- HttpOnly flag ---
        if not cookie["httponly"]:
            findings.append(
                Vulnerability(
                    title=f"Cookie sem flag HttpOnly: {name}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The cookie '{name}' is missing the HttpOnly attribute.  "
                        "JavaScript code (including injected XSS payloads) can read "
                        "this cookie via document.cookie, enabling session hijacking."
                    ),
                    evidence=f"Set-Cookie: {name}=...; [HttpOnly flag absent]",
                    recommendation=f"Add the HttpOnly flag: Set-Cookie: {name}=...; HttpOnly; ...",
                )
            )

        # --- SameSite attribute ---
        if not cookie["samesite"]:
            findings.append(
                Vulnerability(
                    title=f"Cookie sem atributo SameSite: {name}",
                    severity=Severity.LOW,
                    description=(
                        f"The cookie '{name}' has no SameSite attribute.  "
                        "Modern browsers default to Lax, but the explicit absence "
                        "increases CSRF risk on older browsers and non-idempotent "
                        "GET requests."
                    ),
                    evidence=f"Set-Cookie: {name}=...; [SameSite attribute absent]",
                    recommendation=(
                        f"Add: Set-Cookie: {name}=...; SameSite=Strict  "
                        "(or Lax if cross-site GET navigation is needed)."
                    ),
                )
            )

    return findings