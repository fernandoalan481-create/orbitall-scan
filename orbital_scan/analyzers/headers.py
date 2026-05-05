"""
analyzers/headers.py — Módulo de análise de headers de segurança HTTP

Este módulo avalia os headers da resposta HTTP com foco na ausência ou
configuração fraca de diretivas de segurança importantes.

Cada header ausente ou mal configurado é convertido em uma vulnerabilidade
com severidade definida, baseada no impacto real que esse tipo de falha
pode ter em ataques web comuns.

## O que é analisado

- Headers de proteção contra XSS, clickjacking e MIME sniffing
- Política de segurança de conteúdo (CSP)
- Força de transporte via HTTPS (HSTS)
- Outras diretivas de hardening de navegador

## Abordagem

A análise é baseada em comparação direta entre headers esperados e os
retornados pelo servidor, priorizando simplicidade e confiabilidade.

## Referências

- OWASP Secure Headers Project
  https://owasp.org/www-project-secure-headers/

- Mozilla Observatory
  https://observatory.mozilla.org/
"""

from typing import Dict, List
from core.models import Severity, Vulnerability

SECURITY_HEADERS: Dict[str, tuple] = {
    "Content-Security-Policy": (
        Severity.HIGH,
        (
            "Content-Security-Policy (CSP) was not found in the response. "
            "Without CSP the browser has no whitelist of trusted content sources, "
            "making the application vulnerable to Cross-Site Scripting (XSS) and "
            "data-injection attacks."
        ),
        "Add a strict CSP: Content-Security-Policy: default-src 'self'; ...",
    ),
    "Strict-Transport-Security": (
        Severity.HIGH,
        (
            "HTTP Strict-Transport-Security (HSTS) is absent.  Without HSTS, "
            "browsers may silently downgrade HTTPS connections to HTTP, enabling "
            "SSL-stripping and man-in-the-middle attacks."
        ),
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        (
            "X-Frame-Options header is missing.  The page can be embedded inside "
            "an <iframe> on a malicious site, enabling Clickjacking attacks that "
            "trick users into performing unintended actions."
        ),
        "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed).",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        (
            "X-Content-Type-Options: nosniff is absent.  Legacy browsers may "
            "MIME-sniff the response and execute files with unexpected content types, "
            "potentially enabling script injection via uploaded content."
        ),
        "Add: X-Content-Type-Options: nosniff",
    ),
    "X-XSS-Protection": (
        Severity.LOW,
        (
            "X-XSS-Protection header is missing.  While deprecated in modern browsers "
            "in favour of CSP, its absence leaves older browsers without the built-in "
            "reflected-XSS filter."
        ),
        "Add: X-XSS-Protection: 1; mode=block",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        (
            "Referrer-Policy is not set.  The browser's default behaviour may send the "
            "full URL (including query strings with sensitive tokens) to third-party "
            "origins via the Referer header."
        ),
        "Add: Referrer-Policy: no-referrer-when-downgrade  (or stricter).",
    ),
    "Permissions-Policy": (
        Severity.LOW,
        (
            "Permissions-Policy (formerly Feature-Policy) is absent.  Without it, "
            "third-party scripts embedded in the page may access powerful browser APIs "
            "(camera, microphone, geolocation) without restriction."
        ),
        "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
}


def analyze(headers: Dict[str, str]) -> List[Vulnerability]:

    normalised = {k.lower(): v for k, v in headers.items()}
    findings: List[Vulnerability] = []

    for header_name, (severity, description, recommendation) in SECURITY_HEADERS.items():
        if header_name.lower() not in normalised:
            findings.append(
                Vulnerability(
                    title=f"Missing header: {header_name}",
                    severity=severity,
                    description=description,
                    evidence=f"Header '{header_name}' was not present in the response.",
                    recommendation=recommendation,
                )
            )

    return findings