"""
analyzers/links.py — Módulo de análise de segurança de hyperlinks

Este módulo avalia links presentes no HTML com foco em padrões comuns
utilizados em phishing, injeção de conteúdo e manipulação de navegação.

## O que é detectado

1. URLs encurtadas ou redirecionadas
   - Serviços como bit.ly, t.co, tinyurl.com
   - Podem ocultar o destino real do link, facilitando ataques de phishing

2. Mixed content (conteúdo misto)
   - Links HTTP dentro de páginas HTTPS
   - Podem permitir interceptação ou modificação de conteúdo em trânsito

3. Reverse tabnapping
   - Uso de `target="_blank"` sem `rel="noopener noreferrer"`
   - Permite que a nova aba manipule a página original

## Abordagem

A análise é baseada em inspeção estática do HTML renderizado, focando em
padrões conhecidos de risco em aplicações web modernas.

## Referências

- OWASP Testing Guide — OTG-CLIENT-006
- MDN Web Docs — rel=noopener
"""

import re
from typing import List
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None  

from core.models import Severity, Vulnerability


SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "ow.ly", "goo.gl",
    "buff.ly", "is.gd", "rb.gy", "short.io", "rebrand.ly",
    "tiny.cc", "lnkd.in", "bl.ink", "cutt.ly", "su.pr",
}


_URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)


def _is_shortener(url: str) -> bool:

    try:
        host = urlparse(url).netloc.lower()
       
        host = host.removeprefix("www.")
        return host in SHORTENER_DOMAINS
    except Exception:
        return False


def analyze(html_body: str, base_url: str) -> List[Vulnerability]:

    if BeautifulSoup is None:
        return [
            Vulnerability(
                title="Módulo bs4 não instalado — análise de links ignorada",
                severity=Severity.LOW,
                description="Install beautifulsoup4 to enable link analysis.",
                evidence="pip install beautifulsoup4",
            )
        ]

    findings: List[Vulnerability] = []
    soup = BeautifulSoup(html_body, "html.parser")
    base_scheme = urlparse(base_url).scheme.lower()

    anchors = soup.find_all("a", href=True)

    shorteners_found: List[str] = []
    mixed_content: List[str] = []
    tabnapping: List[str] = []

    for anchor in anchors:
        href = anchor["href"].strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue

        if _is_shortener(href):
            shorteners_found.append(href)

        if base_scheme == "https" and href.startswith("http://"):
            mixed_content.append(href)


        target = anchor.get("target", "").lower()
        rel = anchor.get("rel", [])
        if isinstance(rel, str):
            rel = rel.split()
        rel_lower = {r.lower() for r in rel}

        if target == "_blank" and not {"noopener", "noreferrer"}.intersection(rel_lower):
            tabnapping.append(href)

    if shorteners_found:
        sample = shorteners_found[:5]
        findings.append(
            Vulnerability(
                title="Links encurtados / redirecionadores detectados",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(shorteners_found)} link(s) using URL shortening services "
                    "were found on the page.  Shortened URLs obscure the real "
                    "destination, enabling phishing, malware distribution, or "
                    "open-redirect abuse via a trusted domain."
                ),
                evidence="Sample URLs: " + ", ".join(sample),
                recommendation=(
                    "Replace shortened URLs with direct links to the destination.  "
                    "If shorteners are necessary (e.g. for analytics), use "
                    "server-side redirectors that can be audited and revoked."
                ),
            )
        )

    if mixed_content:
        sample = mixed_content[:5]
        findings.append(
            Vulnerability(
                title="Mixed-content: links HTTP em página HTTPS",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(mixed_content)} HTTP link(s) found on an HTTPS page.  "
                    "Loading resources over HTTP on an HTTPS page (mixed content) "
                    "allows network attackers to inject malicious content and can "
                    "trigger browser security warnings."
                ),
                evidence="Sample URLs: " + ", ".join(sample),
                recommendation=(
                    "Update all links to use HTTPS.  "
                    "Consider adding a Content-Security-Policy with "
                    "upgrade-insecure-requests."
                ),
            )
        )

    if tabnapping:
        sample = tabnapping[:5]
        findings.append(
            Vulnerability(
                title="Links target=_blank sem rel=noopener noreferrer",
                severity=Severity.LOW,
                description=(
                    f"{len(tabnapping)} link(s) open in a new tab (target=\"_blank\") "
                    "without rel=\"noopener noreferrer\".  The opened page gains a "
                    "reference to the opener via window.opener and can redirect it "
                    "to a phishing page (reverse tabnapping)."
                ),
                evidence="Sample URLs: " + ", ".join(sample),
                recommendation=(
                    'Add rel="noopener noreferrer" to all target="_blank" links.'
                ),
            )
        )

    return findings