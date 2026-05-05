# Orbital Scan

Um scanner simples de vulnerabilidades web feito em Python.

A ideia do projeto é estudar segurança web na prática e entender como pequenas falhas de configuração podem impactar a segurança de um site.

Não tenta ser uma ferramenta complexa como Burp ou ZAP — é mais um laboratório pessoal de aprendizado.

---

## Aviso importante

Esse projeto é apenas educacional.

Use somente em sistemas que você tem permissão para testar.  
Escanear sites sem autorização pode ser ilegal.

---

## O que ele faz

O Orbital Scan analisa uma URL e procura problemas comuns de segurança, como:

- Headers de segurança faltando ou mal configurados
- Cookies sem flags importantes (Secure, HttpOnly, SameSite)
- Formulários inseguros ou incompletos
- Links suspeitos ou encurtados
- Configurações básicas de HTTP/HTTPS

---

# Scan básico
python main.py https://example.com

# Timeout personalizado
python main.py https://example.com -t 20

# Scan autenticado (enviando cookie de sessão)
python main.py https://app.example.com -H "Cookie: session=abc123"

# Múltiplos headers personalizados
python main.py https://example.com -H "Authorization: Bearer token" -H "X-Custom: value"

# Ocultar o banner (útil para redirecionar saída)
python main.py https://example.com --no-banner

## Estrutura do projeto

```text
orbital-scan/
├── main.py
├── http_client.py
├── analyzers/
│   ├── headers.py
│   ├── cookies.py
│   ├── forms.py
│   └── links.py
├── core/
│   ├── scanner_engine.py
│   ├── risk_classifier.py
│   └── models.py
├── output/
│   └── cli_formatter.py
└── requirements.txt
