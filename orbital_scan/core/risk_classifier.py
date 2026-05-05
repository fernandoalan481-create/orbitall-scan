"""
risk_classifier.py — Classificador de risco do scanner

Este módulo transforma uma lista de vulnerabilidades encontradas em um
score numérico de segurança e em uma classificação de risco legível.

## Modelo de pontuação

O scanner parte de uma pontuação perfeita (100) e aplica penalizações
conforme a severidade de cada achado:

- CRÍTICO → −50 pontos  
- ALTO     → −30 pontos  
- MÉDIO    → −20 pontos  
- BAIXO    → −10 pontos  

O valor final é limitado ao intervalo entre 0 e 100.

## Classificação de risco

Após o cálculo do score, o sistema traduz o resultado em uma categoria
mais intuitiva para leitura humana:

- 75–100 → BAIXO  
- 50–74  → MÉDIO  
- 25–49  → ALTO  
- 0–24   → CRÍTICO  

## Objetivo

A ideia é simplificar a interpretação técnica dos resultados, permitindo
que o output do scanner seja útil tanto para análise técnica quanto para
relatórios executivos.
"""

from typing import List
from core.models import Severity, Vulnerability


DEDUCTION_MAP = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 30,
    Severity.MEDIUM: 20,
    Severity.LOW: 10,
}


def compute_risk_score(vulnerabilities: List[Vulnerability]) -> int:

    deduction = sum(DEDUCTION_MAP.get(v.severity, 0) for v in vulnerabilities)
    return max(0, 100 - deduction)


def classify_risk_label(score: int) -> str:

     if score >= 75:
        return "BAIXO"
    elif score >= 50:
        return "MÉDIO"
    elif score >= 30:
        return "MÉDIO"
    elif score >= 25:
        return "ALTO"
    else:
        return "CRÍTICO"
