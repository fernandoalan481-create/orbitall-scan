"""
http_client.py — Wrapper leve em torno do `requests`

Este módulo encapsula a lógica de requisições HTTP para manter o restante
do sistema independente da biblioteca `requests`.

Ele centraliza comportamentos comuns de rede, como timeout, headers e
tratamento de SSL, garantindo consistência em todas as requisições feitas
pelo scanner.

## Responsabilidades

- Definir headers padrão (User-Agent customizado)
- Controlar timeout de requisições
- Medir tempo de resposta (round-trip time)
- Gerenciar verificação SSL com fallback quando necessário
- Retornar um objeto estruturado de resposta para desacoplar o core do `requests`

## Decisão de arquitetura

O objetivo é evitar que outras partes do sistema dependam diretamente da
implementação do `requests`, facilitando:

- Testes unitários com mocks
- Substituição futura da biblioteca HTTP
- Maior clareza na camada de rede

## Observação

Em caso de falha de verificação SSL, o cliente tenta uma segunda requisição
com verificação desativada, registrando aviso para fins de auditoria.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional

import requests
from requests import Response
from requests.exceptions import SSLError

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 "
    "WebVulnScanner/1.0"
)

DEFAULT_TIMEOUT = 10  


@dataclass
class HttpResponse:
 
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time_ms: float
    ssl_verified: bool
    raw: Optional[Response] = field(default=None, repr=False)


def fetch(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    extra_headers: Optional[Dict[str, str]] = None,
) -> HttpResponse:

    headers = {"User-Agent": DEFAULT_UA}
    if extra_headers:
        headers.update(extra_headers)

    ssl_verified = True

    def _do_request(verify: bool) -> Response:
        return requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=verify,
            allow_redirects=True,
        )

    start = time.perf_counter()
    try:
        response = _do_request(verify=True)
    except SSLError:
        
        ssl_verified = False
        response = _do_request(verify=False)
    elapsed_ms = (time.perf_counter() - start) * 1_000

    return HttpResponse(
        url=response.url,
        status_code=response.status_code,
        headers=dict(response.headers),
        body=response.text,
        response_time_ms=round(elapsed_ms, 2),
        ssl_verified=ssl_verified,
        raw=response,
    )