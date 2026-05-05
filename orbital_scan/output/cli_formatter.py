"""
output/cli_formatter.py — Módulo de formatação de saída no terminal

Este módulo é responsável por gerar a saída final do scanner no terminal,
organizando os resultados de forma estruturada e fácil de interpretar.

O objetivo é simular o estilo de ferramentas profissionais de segurança,
como nmap, nikto e sqlmap, com foco em clareza e legibilidade.

## Esquema de cores

A saída utiliza códigos ANSI (via `colorama`) para destacar informações
importantes:

- CRÍTICO / ALTO → vermelho (negrito)
- MÉDIO          → amarelo
- BAIXO          → ciano
- Informações    → branco / azul
- Sucesso        → verde

## Compatibilidade

O uso do `colorama` garante compatibilidade com diferentes sistemas
operacionais e terminais. Caso o terminal não suporte cores, o output
continua legível em modo texto puro.

## Objetivo

Facilitar a leitura rápida dos resultados, permitindo identificar riscos
de forma imediata durante análises de segurança.
"""

from typing import Optional
from core.models import ScanResult, Severity, Vulnerability


try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True) 

    RED    = Fore.RED + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    CYAN   = Fore.CYAN
    GREEN  = Fore.GREEN + Style.BRIGHT
    BLUE   = Fore.BLUE + Style.BRIGHT
    WHITE  = Fore.WHITE + Style.BRIGHT
    DIM    = Style.DIM
    RESET  = Style.RESET_ALL

except ImportError:
    
    RED = YELLOW = CYAN = GREEN = BLUE = WHITE = DIM = RESET = ""


def _severity_color(severity: Severity) -> str:
    return {
        Severity.CRITICAL: RED,
        Severity.HIGH: RED,
        Severity.MEDIUM: YELLOW,
        Severity.LOW: CYAN,
    }.get(severity, WHITE)


def _score_color(score: int) -> str:
    if score >= 75:
        return GREEN
    if score >= 50:
        return YELLOW
    if score >= 25:
        return RED
    return RED + Style.BRIGHT if Style else RED


def _divider(char: str = "─", width: int = 70) -> str:
    return DIM + char * width + RESET


# ---------------------------------------------------------------------------
# API Púlica
# ---------------------------------------------------------------------------

def print_banner() -> None:

    banner = f"""
{BLUE}
{WHITE} $$$$$$\\            $$\\       $$\\   $$\\               $$\\        $$$$$$\\                               
{WHITE}$$  __$$\\           $$ |      \\__|  $$ |              $$ |      $$  __$$\\                              
{WHITE}$$ /  $$ | $$$$$$\\  $$$$$$$\\  $$\\ $$$$$$\\    $$$$$$\\  $$ |      $$ /  \\__| $$$$$$$\\ $$$$$$\\  $$$$$$$\\  
{WHITE}$$ |  $$ |$$  __$$\\ $$  __$$\\ $$ |\\_$$  _|   \\____$$\\ $$ |      \\$$$$$$\\  $$  _____|\\____$$\\ $$  __$$\\ 
{WHITE}$$ |  $$ |$$ |  \\__|$$ |  $$ |$$ |  $$ |     $$$$$$$ |$$ |       \\____$$\\ $$ /      $$$$$$$ |$$ |  $$ |
{WHITE}$$ |  $$ |$$ |      $$ |  $$ |$$ |  $$ |$$\\ $$  __$$ |$$ |      $$\\   $$ |$$ |     $$  __$$ |$$ |  $$ |
{WHITE} $$$$$$  |$$ |      $$$$$$$  |$$ |  \\$$$$  |\\$$$$$$$ |$$ |      \\$$$$$$  |\\$$$$$$$\\\\$$$$$$$ |$$ |  $$ |
{WHITE} \\______/ \\__|      \\_______/ \\__|   \\____/  \\_______|\\__|       \\______/  \\_______|\\_______|\\__|  \\__|
{RESET}
{CYAN}                     Web Vulnerability Scanner  {DIM}v1.0.0  {CYAN}[ Educacional / Portfolio ]{RESET}
{DIM}                     by https://github.com/fernandoalan481-create  │ Use com responsabilidade & com permissão{RESET}
"""
    print(banner)


def print_scan_header(url: str) -> None:
    
    print(_divider())
    print(f"  {WHITE}TARGET{RESET}   : {CYAN}{url}{RESET}")
    print(_divider())
    print()


def print_progress(message: str) -> None:
    
    print(f"  {BLUE}[*]{RESET} {message}")


def print_finding(vuln: Vulnerability, index: int) -> None:

    color = _severity_color(vuln.severity)
    severity_tag = f"{color}[{vuln.severity.value}]{RESET}"

    print(f"\n  {severity_tag}  {WHITE}{vuln.title}{RESET}")
    print(f"  {DIM}{'─' * 65}{RESET}")
    print(f"  {DIM}Descrição  :{RESET} {vuln.description}")
    print(f"  {DIM}Evidência  :{RESET} {CYAN}{vuln.evidence}{RESET}")
    if vuln.recommendation:
        print(f"  {DIM}Correção   :{RESET} {GREEN}{vuln.recommendation}{RESET}")


def print_report(result: ScanResult) -> None:

    print(f"\n\n{_divider('═')}")
    print(f"  {WHITE}RELATÓRIO FINAL — WEB VULNERABILITY SCAN{RESET}")
    print(_divider('═'))


    print(f"\n  {WHITE}Alvo         :{RESET} {result.target_url}")
    print(f"  {WHITE}Status HTTP  :{RESET} {result.status_code}")
    print(f"  {WHITE}Tempo resp.  :{RESET} {result.response_time_ms} ms")

   
    total = len(result.vulnerabilities)
    print(f"\n  {WHITE}Findings     :{RESET} {total} vulnerabilidade(s) encontrada(s)")
    print(f"    {RED}Crítico  : {result.critical_count}{RESET}")
    print(f"    {RED}Alto     : {result.high_count}{RESET}")
    print(f"    {YELLOW}Médio    : {result.medium_count}{RESET}")
    print(f"    {CYAN}Baixo    : {result.low_count}{RESET}")

    
    score = result.risk_score
    score_color = _score_color(score)
    filled = int(score / 5)          
    empty = 20 - filled
    bar = "█" * filled + "░" * empty

    print(f"\n  {WHITE}Risk Score   :{RESET} {score_color}{score:>3}/100{RESET}  "
          f"[{score_color}{bar}{RESET}]  "
          f"{score_color}{result.risk_label}{RESET}")

    
    if result.vulnerabilities:
        print(f"\n{_divider()}")
        print(f"  {WHITE}DETALHAMENTO DAS VULNERABILIDADES{RESET}")
        print(_divider())
        for i, vuln in enumerate(result.vulnerabilities, start=1):
            print_finding(vuln, i)

    print(f"\n{_divider('═')}")
    print(f"  {DIM}Scan concluído.  Use os resultados apenas em ambientes autorizados.{RESET}")
    print(_divider('═'))
    print()


def print_error(message: str) -> None:
   
    print(f"\n  {RED}[ERRO]{RESET} {message}\n")
