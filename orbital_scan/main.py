"""
main.py — Ponto de entrada (CLI) do Web Vulnerability Scanner

Este arquivo é responsável por iniciar a ferramenta via linha de comando,
processar os argumentos do usuário e acionar o fluxo principal do scanner.

## Uso

    python main.py <URL> [opções]

## Opções

- -t, --timeout INT  
  Define o tempo limite das requisições HTTP (padrão: 10s)

- -H, --header KEY:VAL  
  Permite adicionar headers personalizados à requisição (pode ser usado múltiplas vezes)

- --no-banner  
  Desativa a exibição do banner ASCII ao iniciar a ferramenta

## Exemplos

    python main.py https://example.com
    python main.py https://alvo.local -t 15
    python main.py https://app.local -H "Authorization: Bearer token"

## Observação

A ferramenta deve ser utilizada apenas em ambientes autorizados e com permissão explícita.
"""

import argparse
import sys

from core import scanner_engine
from output import cli_formatter


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="orbital-scan",
        description="Web Vulnerability Scanner — Ferramenta educacional e de portfólio para análise de segurança em aplicações web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "⚠ AVISO ÉTICO E LEGAL\n\n"
            "   o uso não autorizado pode violar leis como CFAA (EUA), LGPD e Marco Civil da Internet (Brasil)."
        ),
    )

    parser.add_argument(
        "url",
        metavar="URL",
        help="Target URL to scan (e.g. https://example.com)",
    )
    parser.add_argument(
        "-t", "--timeout",
        metavar="INT",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-H", "--header",
        metavar="KEY:VALUE",
        action="append",
        default=[],
        dest="headers",
        help="Custom header (can be specified multiple times)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII art banner",
    )

    return parser.parse_args()


def parse_custom_headers(raw_headers: list) -> dict:

    result = {}
    for item in raw_headers:
        if ":" in item:
            key, _, value = item.partition(":")
            result[key.strip()] = value.strip()
    return result


def main() -> int:
    args = parse_args()

    if not args.no_banner:
        cli_formatter.print_banner()

    url = args.url
   
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    extra_headers = parse_custom_headers(args.headers)

    cli_formatter.print_scan_header(url)
    cli_formatter.print_progress("Iniciando requisição HTTP …")

    try:
        cli_formatter.print_progress("Analisando headers de segurança …")
        cli_formatter.print_progress("Analisando cookies …")
        cli_formatter.print_progress("Analisando formulários HTML …")
        cli_formatter.print_progress("Analisando links …")

        result = scanner_engine.scan(
            url=url,
            timeout=args.timeout,
            extra_headers=extra_headers or None,
        )

    except Exception as exc:
        cli_formatter.print_error(
            f"Não foi possível conectar ao alvo: {exc}\n"
            "  Verifique a URL, a conectividade de rede e o timeout."
        )
        return 1

    cli_formatter.print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())