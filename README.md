# LogAnalyzer: Analisador Lógico de Logs de Servidor

## 1. Membros do Grupo
* Gustavo Henrique
* Lucas Cassio
* Náthally Fernandes
* Rafael Chimicatti

## 2. Explicação do Sistema
O **LogAnalyzer** é uma aplicação de linha de comando (CLI) desenvolvida para processar e analisar arquivos de log de servidores web (como Nginx ou Apache). O sistema consome arquivos de texto bruto ou estruturados (JSON) e gera um relatório detalhado em formato `.csv` focado em saúde da aplicação e segurança.

O sistema extrai métricas vitais e identifica anomalias, incluindo:

* **Detecção de Anomalias de Tráfego:** Identificação de IPs com excesso de erros `4xx` ou `5xx` em um curto espaço de tempo (indicativo de problemas de *rate limiting* ou ataques de negação de serviço).
* **Análise de Performance:** Cálculo do tempo médio de resposta para *endpoints* específicos da API.
* **Auditoria de Segurança Básica:** Varredura nas URLs acessadas para alertar sobre requisições suspeitas, como padrões comuns de *SQL Injection* ou *Cross-Site Scripting* (XSS).

## 3. Foco em Qualidade e Manutenção (Objetivo do TP)
A arquitetura do LogAnalyzer foi desenhada com forte separação de responsabilidades: a lógica de *parsing* (interpretação das linhas de log) é isolada da lógica de negócios (cálculo de anomalias) e da infraestrutura (leitura/escrita de arquivos).

O principal objetivo desta aplicação é demonstrar o valor prático dos testes automatizados na prevenção de regressões em sistemas com regras de negócio complexas. Diferente de textos comuns, arquivos de log possuem formatos rígidos, mas frequentemente apresentam casos extremos (*edge cases*). Através da nossa suíte de testes, buscaremos evidenciar como a cobertura de código garante que o sistema continue funcionando mesmo diante de atualizações ou refatorações críticas.
