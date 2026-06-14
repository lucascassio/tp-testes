# LogAnalyzer: Analisador Web de Logs de Servidor

## 1. Membros do Grupo
- Gustavo Henrique
- Lucas Cassio
- Náthally Fernandes
- Rafael Chimicatti

## 2. Explicação do Sistema
O **LogAnalyzer** é uma aplicação web desenvolvida para processar e analisar arquivos de log de servidores web (como Nginx ou Apache). O sistema consome arquivos de texto bruto contendo logs no formato *combined* e exibe os resultados diretamente no navegador.

O sistema extrai métricas vitais e identifica anomalias, incluindo:

- **Detecção de Anomalias de Tráfego:** Identificação de IPs com excesso de erros `4xx` ou `5xx` (indicativo de ataques de força bruta ou *rate limiting*).
- **Análise de Performance:** Cálculo do tempo médio de resposta para cada *endpoint* da API.
- **Auditoria de Segurança:** Varredura nas URLs acessadas para alertar sobre requisições suspeitas, como padrões de *SQL Injection*, *Cross-Site Scripting* (XSS) e *Path Traversal*.

### Funcionalidades
- Upload de arquivo de log via drag-and-drop ou seleção de arquivo
- Entrada de logs via área de texto (*paste*)
- Dashboard interativo com abas para: Log Entries, Anomalies, Performance e Security
- Download do relatório completo em formato texto
- Amostra de dados pré-carregada para testes rápidos

## 3. Tecnologias Utilizadas
- **Python 3.11** — Linguagem de programação principal
- **FastAPI** — Framework web para a API REST
- **Pytest** — Framework de testes unitários e de integração
- **Coverage.py / pytest-cov** — Medição de cobertura de código
- **HTML/CSS/JS Vanilla** — Frontend sem dependências externas
- **GitHub Actions** — CI/CD automatizado em Linux, macOS e Windows
- **Codecov** — Publicação de relatórios de cobertura online

## 4. Como Executar os Testes Localmente

### Pré-requisitos
- Python 3.11+
- pip

### Instalação
```bash
pip install -r requirements.txt
```

### Executar todos os testes
```bash
pytest tests/ -v
```

### Executar testes com cobertura
```bash
pytest tests/ --cov=app --cov-report=term-missing
```

### Gerar relatório de cobertura em XML (para Codecov)
```bash
pytest tests/ --cov=app --cov-report=xml
```

### Executar a aplicação
```bash
uvicorn app.main:app --reload
```
Acesse http://localhost:8000 no navegador.

## 5. Estrutura do Projeto
```
├── app/
│   ├── __init__.py
│   ├── main.py          # Aplicação FastAPI
│   ├── models.py        # Modelo de dados LogEntry
│   ├── parser.py        # Parser de logs Nginx/Apache
│   ├── analyzers.py     # Analisadores (anomalias, performance, segurança)
│   ├── reporters.py     # Geradores de relatório CSV
│   └── templates/
│       └── index.html   # Frontend vanilla
├── tests/
│   ├── __init__.py
│   ├── test_parser.py              # 25 testes de unidade
│   ├── test_anomaly_detector.py    # 9 testes de unidade
│   ├── test_performance_analyzer.py # 7 testes de unidade
│   ├── test_security_auditor.py    # 11 testes de unidade
│   ├── test_reporters.py           # 8 testes de unidade
│   └── test_integration.py         # 8 testes de integração
├── .github/workflows/tests.yml     # CI/CD
├── requirements.txt
├── .coveragerc
└── README.md
```

## 6. CI/CD e Cobertura
Os testes são executados automaticamente a cada commit via **GitHub Actions** nos sistemas operacionais **Linux**, **macOS** e **Windows**. O relatório de cobertura é enviado para o **Codecov**.

[![Tests](https://github.com/lucascassio/log-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/lucascassio/log-analyzer/actions/workflows/tests.yml)
[![codecov](https://codecov.io/github/lucascassio/log-analyzer/branch/main/graph/badge.svg)](https://codecov.io/github/lucascassio/log-analyzer)

## 7. Métricas de Teste
- **70 testes** no total (62 unitários + 8 integração)
- **95% de cobertura** de código
