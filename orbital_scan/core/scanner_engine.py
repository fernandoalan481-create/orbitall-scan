"""
core/scanner_engine.py — Camada de orquestração do scanner de vulnerabilidades

Este módulo é o “coração” do sistema. Ele coordena todo o fluxo de análise,
desde a requisição HTTP até a geração do resultado final do scan.

## Responsabilidades

1. Realizar a requisição HTTP do alvo via `http_client`
2. Executar todos os módulos de análise (analyzers) em sequência
3. Consolidar os achados em um objeto `ScanResult`
4. Calcular score de risco e classificação usando o `risk_classifier`
5. Retornar um resultado completo e pronto para exibição ou exportação

## Arquitetura

Cada analisador foi projetado como um módulo independente, recebendo
estruturas simples de dados (strings, dicts, listas), em vez de depender
diretamente do objeto de resposta HTTP.

Isso garante:

- Baixo acoplamento entre camadas
- Facilidade de testes unitários
- Possibilidade de adicionar novos analisadores sem modificar o core
- Maior clareza na separação de responsabilidades

## Decisão de design

O engine não contém lógica de detecção de vulnerabilidades diretamente.
Ele apenas orquestra o fluxo, mantendo o sistema modular e extensível.
"""

from typing import Optional, Dict
from http_client import fetch, HttpResponse
from analyzers import headers as headers_analyzer
from analyzers import cookies as cookies_analyzer
from analyzers import forms as forms_analyzer
from analyzers import links as links_analyzer
from core.models import ScanResult, Vulnerability, Severity
from core import risk_classifier


def scan(
    url: str,
    timeout: int = 10,
    extra_headers: Optional[Dict[str, str]] = None,
) -> ScanResult:
 
    response: HttpResponse = fetch(url, timeout=timeout, extra_headers=extra_headers)

    result = ScanResult(
        target_url=response.url,
        status_code=response.status_code,
        response_time_ms=response.response_time_ms,
    )

    if not response.ssl_verified:
        result.add_vulnerability(
            Vulnerability(
                title="Certificado SSL inválido ou auto-assinado",
                severity=Severity.HIGH,
                description=(
                    "The server's SSL/TLS certificate could not be verified.  "
                    "This may indicate a self-signed certificate, an expired "
                    "certificate, or a man-in-the-middle proxy.  "
                    "Browsers will display security warnings, damaging user trust."
                ),
                evidence=(
                    f"Request to {url} succeeded only after disabling SSL verification."
                ),
                recommendation=(
                    "Install a valid certificate from a trusted CA "
                    "(e.g. Let's Encrypt for free DV certificates)."
                ),
            )
        )


    _run_analyser(result, headers_analyzer.analyze, response.headers)
    _run_analyser(result, cookies_analyzer.analyze, response)
    _run_analyser(result, forms_analyzer.analyze, response.body, response.url)
    _run_analyser(result, links_analyzer.analyze, response.body, response.url)


    result.risk_score = risk_classifier.compute_risk_score(result.vulnerabilities)
    result.risk_label = risk_classifier.classify_risk_label(result.risk_score)

    return result


def _run_analyser(result: ScanResult, analyser_fn, *args) -> None:
 
    try:
        findings = analyser_fn(*args)
        for vuln in findings:
            result.add_vulnerability(vuln)
    except Exception as exc:
  
        result.add_vulnerability(
            Vulnerability(
                title=f"Erro interno no analisador: {analyser_fn.__module__}",
                severity=Severity.LOW,
                description=f"An unexpected error occurred in the analyser: {exc}",
                evidence=repr(exc),
            )
        )