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

## 6. Evidência do Valor dos Testes Automatizados

A arquitetura do sistema foi projetada com **separação estrita de responsabilidades**, o que permite testar cada camada de forma isolada e garante que mudanças em um módulo não quebrem outros. Esta seção demonstra, com exemplos concretos, como a suíte de testes previne regressões.

### 6.1 Camadas Independentes e Testáveis

| Camada | Módulo | O que testa | Por que é importante |
|--------|--------|-------------|---------------------|
| Parsing | `parser.py` | Interpretação de cada linha de log | Erros de parsing quebrariam toda análise |
| Negócio | `analyzers.py` | Regras de anomalia, performance, segurança | Lógica crítica que não pode regredir |
| Relatório | `reporters.py` | Geração de CSV/relatórios | Formato de saída deve ser consistente |
| Infra/API | `main.py` | Endpoints HTTP, upload, respostas | Interface com o usuário final |

### 6.2 Edge Cases Cobertos pelo Parser (25 testes)

O parser é a porta de entrada. Se falhar, tudo falha. Por isso é o módulo com mais testes:

| Edge Case | Exemplo de Entrada | Comportamento Esperado | Evita |
|-----------|-------------------|----------------------|-------|
| Linha vazia | `""` | Retorna `None` | Crash ao processar arquivos com linhas em branco |
| Linha malformada | `"texto qualquer"` | Retorna `None` | Interpretar lixo como log válido |
| IPv6 | `::1 - - [...]` | Extrai `::1` corretamente | Ignorar tráfego IPv6 |
| URL com espaços | `/search?q=hello world` | Preserva espaços na URL | Perder parte da query string |
| Request sem HTTP | `GET /api/data` | Protocol vazio, path preservado | Falhar em formatos não-padrão |
| Timestamp inválido | `"not-a-date"` | `timestamp = None` | Crash na conversão de data |
| Response time não numérico | `"slow"` como último campo | `request_time = 0.0` | Crash na conversão numérica |
| Status code não numérico | `ABC` como status | Retorna `None` (linha inválida) | Corromper estatísticas |

### 6.3 Exemplo Concreto de Prevenção de Regressão

Durante o desenvolvimento, o `parse_request()` original usava `split(" ", 2)` para separar método, path e protocolo. Isso funcionava para URLs simples como `/api/users`, mas **quebrava silenciosamente** com URLs contendo espaços (ex: `/search?q=hello world`), truncando o path.

O teste `test_request_with_spaces_in_url` foi adicionado especificamente para este caso:

```python
def test_request_with_spaces_in_url(self):
    m, p, proto = parse_request("GET /search?q=hello world HTTP/1.1")
    assert p == "/search?q=hello world"  # Garante path completo
```

Após refatorar `parse_request()` para usar um algoritmo que identifica o protocolo pelo último token (em vez de assumir 3 tokens fixos), **todos os 25 testes do parser continuaram passando**, comprovando que a refatoração não introduziu regressões.

### 6.4 Cobertura como Rede de Segurança

A suíte atual conta com **78 testes** (70 unitários + 8 integração) e **99% de cobertura de código**. Cada linha não coberta é uma oportunidade para um bug não detectado. As 2 linhas restantes não cobertas (`parser.py:42,88-89`) são branches defensivos para casos extremos de arrays vazios que exigiriam manipulação interna da implementação para serem acionados.

## 7. CI/CD e Cobertura
Os testes são executados automaticamente a cada commit via **GitHub Actions** nos sistemas operacionais **Linux**, **macOS** e **Windows**. O relatório de cobertura é enviado para o **Codecov**.

[![Tests](https://github.com/lucascassio/tp-testes/actions/workflows/tests.yml/badge.svg)](https://github.com/lucascassio/tp-testes/actions/workflows/tests.yml)
[![codecov](https://codecov.io/github/lucascassio/tp-testes/branch/main/graph/badge.svg)](https://codecov.io/github/lucascassio/tp-testes)

## 8. Métricas de Teste
- **78 testes** no total (70 unitários + 8 integração)
- **99% de cobertura** de código
