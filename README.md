# ISP Threat Scanner Edge 

Uma projeto para análise técnica da superfície de exposição pública de Sistemas Autônomos (ASN). Focada em **Inteligência de Fontes Abertas (OSINT)** e coleta passiva de dados.

---

## Como Executar (Quick Start)

Este projeto está pronto para ser executado via **Docker**, garantindo isolamento total e facilidade de deploy em qualquer ambiente.

### Via Docker Compose (Recomendado)
Certifique-se de ter o Docker instalado e execute:

```bash
# Sobe o container em segundo plano
docker-compose up --build -d
```
Acesse a interface em: **[http://localhost:8000](http://localhost:8000)**

### Via Python Nativo
Se preferir rodar localmente sem Docker:

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
2. Inicie o servidor:
   ```bash
   python app.py
   ```
3. Acesse em: `http://localhost:8000`

---

## Funcionamento Técnico

O scanner realiza a análise exclusivamente através de fontes de dados públicas, sem executar varreduras ativas ou interações diretas com a infraestrutura do alvo.

1.  **Mapeamento BGP**: Consulta ao `RIPE Stat` para identificar todos os prefixos IPv4 anunciados pelo ASN e o nome do detentor (holder).
2.  **Agregação Passiva**: Integração com a API do `Shodan InternetDB` para consumir dados de portas e serviços já indexados.
3.  **Threat Intel**: Verificação de reputação e indicadores de comprometimento (IoCs) históricos via `AlienVault OTX`.
4.  **Google Dorks Engine**: Geração dinâmica de consultas avançadas para identificar painéis de administração, backups expostos e arquivos sensíveis indexados.
5.  **Subdomain Discovery**: Descoberta passiva de subdomínios através de logs de Transparência de Certificados (Cert-Transparency via `crt.sh`).
6.  **Motor de Risco**: Algoritmo de pontuação proprietário que avalia a severidade com base em protocolos expostos, CVEs, reputação e superfície de ataque (subdomínios).
7.  **Relatórios Corporativos**: Geração automática de relatórios técnicos em PDF/Impressão com layout profissional.

---

## Diferenciais e Stack

*   **Backend Concorrente**: Desenvolvido em **Python 3.11+ / FastAPI** com uso intensivo de `asyncio` e `httpx` para consultas ultrarrápidas.
*   **Interface Premium**: Frontend moderno em Vanilla JS, com suporte a **Dark Mode**, gráficos dinâmicos via `Chart.js` e feedback em tempo real via **WebSockets**.
*   **Persistência Segura**: Banco de dados `SQLite` para histórico de análises, com volume configurado no Docker para persistência de dados.
*   **Detecção de Ambiente**: Sistema inteligente que detecta se está rodando em Docker ou Nativo, adaptando-se visualmente.

---

## Configurações Avançadas

Para obter 100% de precisão e cobertura global (Modo Full-Index), você pode definir sua chave de API do Shodan:

```bash
# Docker Compose (.env ou environment)
SHODAN_API_KEY="SUA_CHAVE_AQUI"

# Windows (PowerShell)
$env:SHODAN_API_KEY="SUA_CHAVE_AQUI"
```

---

## Manutenção e Limpeza

Para redefinir o ambiente local (remover banco de dados e caches):
```bash
python clean.py
```

---

## Uso Ético e Segurança

Esta ferramenta foi desenvolvida como uma Prova de Conceito (PoC) para fins educacionais e de auditoria preventiva. 
*   **Privacidade**: O scanner respeita as políticas das APIs consultadas e não realiza ataques ativos (scans de porta diretos).
*   **Segurança**: Nunca exponha sua `SHODAN_API_KEY` publicamente. Utilize ambientes controlados para análise de infraestruturas críticas.

---
