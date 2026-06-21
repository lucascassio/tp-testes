# LogAnalyzer: Analisador Web de Logs de Servidor

## 1. Membros do Grupo
- Gustavo Henrique
- Lucas Cassio
- Náthally Fernandes
- Rafael Chimicatti

## 2. Explicação do Sistema
O **LogAnalyzer** é uma aplicação web para processar e analisar arquivos de log de servidores web (Nginx/Apache) no formato *combined*. O sistema consome logs brutos e exibe métricas diretamente no navegador.

### Funcionalidades
- **Detecção de Anomalias de Tráfego:** IPs com excesso de erros 4xx/5xx (força bruta, rate limiting)
- **Análise de Performance:** Tempo médio de resposta por endpoint da API
- **Auditoria de Segurança:** Varredura de URLs para SQL Injection, XSS e Path Traversal
- Upload de arquivo via drag-and-drop ou seleção
- Entrada de logs via área de texto (paste)
- Dashboard interativo com abas: Entries, Anomalies, Performance, Security
- Download do relatório completo em texto
- 7 cenários de amostra pré-carregados para testes rápidos

## 3. Tecnologias Utilizadas
- **Python 3.11** — Linguagem principal
- **FastAPI** — Framework web para API REST
- **Pytest** — Framework de testes (parametrize, fixtures, markers)
- **Hypothesis** — Property-based testing (fuzz testing com dados gerados)
- **Coverage.py / pytest-cov** — Medição de cobertura
- **HTTPX** — Cliente HTTP para testes e2e com servidor real
- **Uvicorn** — Servidor ASGI (produção e testes e2e)
- **HTML/CSS/JS Vanilla** — Frontend sem dependências externas
- **GitHub Actions** — CI/CD em Linux, macOS e Windows
- **Codecov** — Relatórios de cobertura online

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

### Executar por camada (markers)
```bash
pytest tests/ -m unit          # 82 testes de unidade (rápidos, isolados)
pytest tests/ -m integration   # 69 testes de integração (HTTP via TestClient)
pytest tests/ -m e2e           # 15 testes e2e (servidor uvicorn real)
```

### Executar com cobertura
```bash
pytest tests/ --cov=app --cov-report=term-missing
```

### Gerar relatório XML (para Codecov)
```bash
pytest tests/ --cov=app --cov-report=xml
```

### Executar a aplicação
```bash
uvicorn app.main:app --reload
```
Acesse http://localhost:8000

## 5. Estrutura do Projeto
```
├── app/
│   ├── __init__.py
│   ├── main.py              # Aplicação FastAPI (endpoints REST)
│   ├── models.py            # Modelo de dados LogEntry (dataclass)
│   ├── parser.py            # Parser de logs Nginx/Apache (regex)
│   ├── analyzers.py         # Analisadores (anomalias, performance, segurança)
│   ├── reporters.py         # Geradores de relatório CSV
│   ├── samples.py           # 7 cenários de log pré-gerados
│   └── templates/
│       └── index.html       # Frontend vanilla (HTML/CSS/JS)
├── tests/
│   ├── conftest.py                    # Fixtures compartilhados (make_entry, etc)
│   ├── unit/
│   │   ├── test_parser.py             # 35 testes — parsing de logs
│   │   ├── test_anomaly_detector.py   # 10 testes — detecção de anomalias
│   │   ├── test_security_auditor.py   # 15 testes — auditoria de segurança
│   │   ├── test_performance_analyzer.py # 8 testes — análise de performance
│   │   ├── test_reporters.py          # 8 testes — geração de CSV/relatórios
│   │   └── test_property.py           # 7 testes — property-based (Hypothesis)
│   ├── integration/
│   │   ├── conftest.py                # Fixture TestClient
│   │   ├── test_api.py                # 16 testes — endpoints HTTP
│   │   └── test_samples.py            # 53 testes — cenários com analisadores reais
│   └── e2e/
│       ├── conftest.py                # Fixture live_server (uvicorn + polling)
│       └── test_pipeline.py           # 15 testes — servidor real + httpx
├── .github/workflows/tests.yml        # CI/CD (Linux, macOS, Windows + Codecov)
├── pytest.ini                         # Config pytest (markers)
├── requirements.txt
└── README.md
```

## 6. Estratégia de Testes

### 6.1 Três Camadas de Teste

| Camada | Framework | Quantidade | O que testa |
|--------|-----------|-----------|-------------|
| **Unit** | Pytest + Hypothesis | 82 | Funções isoladas, sem dependências externas |
| **Integration** | TestClient (FastAPI) | 69 | Múltiplos componentes reais, HTTP stack |
| **E2E** | Uvicorn + HTTPX | 15 | Servidor real, porta livre, polling de readiness |

### 6.2 Técnicas Utilizadas
- **Parametrize:** Testes de SQLi, XSS, Traversal agrupados em um método com `@pytest.mark.parametrize`
- **Fixtures:** `make_entry` factory, `sample_multiline_log`, analyzers pré-configurados
- **Markers:** `unit`, `integration`, `e2e` para filtragem por camada
- **Property-based testing:** Hypothesis gera centenas de entradas aleatórias para validar invariantes do parser e auditor de segurança
- **Assert messages:** Toda assertion multi-campo inclui mensagem descritiva de falha
- **Superset assertions:** `assert result >= expected` em vez de igualdade exata (resiliente a novos campos)

### 6.3 Cobertura como Rede de Segurança
A suíte atual conta com **166 testes** e **100% de cobertura** (linhas e branches). Durante o desenvolvimento, a cobertura guiou a adição de testes para código não exercitado (ex: geradores de cenários em `samples.py` estavam em 25%).

## 7. CI/CD e Cobertura
Os testes são executados automaticamente a cada commit via **GitHub Actions** nos sistemas operacionais **Linux**, **macOS** e **Windows**. O relatório de cobertura é enviado para o **Codecov**.

[![Tests](https://github.com/lucascassio/tp-testes/actions/workflows/tests.yml/badge.svg)](https://github.com/lucascassio/tp-testes/actions/workflows/tests.yml)
[![codecov](https://codecov.io/github/lucascassio/tp-testes/branch/main/graph/badge.svg)](https://codecov.io/github/lucascassio/tp-testes)

## 8. Métricas de Teste
- **166 testes** no total (82 unitários + 69 integração + 15 e2e)
- **100% de cobertura** de código (linhas e branches)
- **7 cenários** de log pré-gerados testados exaustivamente
- **3 sistemas operacionais** na CI (Linux, macOS, Windows)
