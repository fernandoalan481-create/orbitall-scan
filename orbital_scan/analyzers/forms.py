"""
analyzers/forms.py — Módulo de análise de segurança de formulários HTML

Este módulo analisa elementos <form> dentro do HTML da página, com foco em
identificar padrões comuns de insegurança no envio de dados.

## O que é verificado

1. Submissão de dados via HTTP sem criptografia (sem TLS)
   - Pode expor credenciais e informações sensíveis durante a transmissão

2. Formulários sem atributo action
   - O envio ocorre para a própria URL atual, o que pode gerar comportamento
     inesperado e dificultar auditoria

3. Ausência de proteção contra CSRF (heurística)
   - Verificação não determinística, usada apenas como indicação de risco
   - Pode indicar falta de tokens anti-CSRF em formulários sensíveis

## Abordagem técnica

Utiliza o BeautifulSoup para parsing do HTML, garantindo compatibilidade com:

- HTML malformado
- Estruturas aninhadas
- Variações de aspas e atributos

## Observação

As verificações são baseadas em heurísticas de segurança e não substituem
uma auditoria manual completa ou testes dinâmicos com exploração ativa.

## Referências

- OWASP Testing Guide — OTG-AUTHN-001
- OWASP CSRF Prevention Cheat Sheet
"""

from typing import List
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None  

from core.models import Severity, Vulnerability

CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "_token", "csrf_token",
    "authenticity_token", "__requestverificationtoken",
    "xsrf-token", "_csrf",
}


def analyze(html_body: str, base_url: str) -> List[Vulnerability]:

    if BeautifulSoup is None:
        return [
            Vulnerability(
                title="Módulo bs4 não instalado — análise de forms ignorada",
                severity=Severity.LOW,
                description="Install beautifulsoup4 to enable form analysis.",
                evidence="pip install beautifulsoup4",
            )
        ]

    findings: List[Vulnerability] = []
    soup = BeautifulSoup(html_body, "html.parser")
    forms = soup.find_all("form")

    if not forms:
        return findings

    base_scheme = urlparse(base_url).scheme.lower()  

    for idx, form in enumerate(forms, start=1):
        action = form.get("action", "").strip()
        method = form.get("method", "get").strip().lower()

        if not action:
            findings.append(
                Vulnerability(
                    title=f"Formulário #{idx} sem atributo action",
                    severity=Severity.LOW,
                    description=(
                        f"Form #{idx} has no action attribute.  The browser will "
                        "submit the form to the current page URL, which may be "
                        "unintended and makes security review harder."
                    ),
                    evidence=f"<form method=\"{method}\"> [action absent]",
                    recommendation="Always specify an explicit action URL.",
                )
            )

        if method == "post":
            action_scheme = urlparse(action).scheme.lower() if action else ""

            submits_over_http = (
                action_scheme == "http"  
                or (action_scheme == "" and base_scheme == "http")  
            )

            if submits_over_http:
                findings.append(
                    Vulnerability(
                        title=f"Formulário #{idx} envia dados via HTTP inseguro",
                        severity=Severity.HIGH,
                        description=(
                            f"Form #{idx} uses POST over plain HTTP, meaning credentials "
                            "and sensitive inputs are transmitted in cleartext.  An "
                            "attacker on the same network can intercept them trivially."
                        ),
                        evidence=(
                            f"<form method=\"post\" action=\"{action or '(relativo)'}\"> "
                            f"[base URL scheme: {base_scheme}]"
                        ),
                        recommendation=(
                            "Serve the page and the form action over HTTPS.  "
                            "Redirect all HTTP traffic to HTTPS."
                        ),
                    )
                )

        if method == "post":
            input_names = {
                inp.get("name", "").lower()
                for inp in form.find_all("input")
                if inp.get("name")
            }
            has_csrf_token = bool(input_names & CSRF_TOKEN_NAMES)

            if not has_csrf_token:
                findings.append(
                    Vulnerability(
                        title=f"Formulário #{idx} sem token CSRF aparente",
                        severity=Severity.LOW,
                        description=(
                            f"Form #{idx} (POST) has no input field with a name "
                            "matching common CSRF-token patterns.  This is a "
                            "heuristic check — verify manually whether CSRF "
                            "protection is implemented at the framework level."
                        ),
                        evidence=(
                            f"Input names found: {sorted(input_names) or '(nenhum)'}"
                        ),
                        recommendation=(
                            "Implement the Synchroniser Token Pattern or "
                            "SameSite=Strict cookies as a CSRF defence."
                        ),
                    )
                )

    return findings