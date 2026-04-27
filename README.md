# ReconToolkit 🕵️

> Automação de reconhecimento passivo e semi-passivo: DNS, WHOIS, geolocalização de IP, enumeração de subdomínios, headers HTTP e verificação de portas comuns.

Desenvolvido como parte de um portfólio de cibersegurança. Apenas para fins educacionais — sempre obtenha autorização explícita antes de realizar reconhecimento em qualquer alvo.

---

## Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| `dns` | Resolução de registros A, MX, NS, TXT e PTR (reverso) |
| `whois` | Informações de registro do domínio (registrar, datas, nameservers) |
| `geoip` | Geolocalização do IP: país, cidade, ISP, ASN, coordenadas |
| `subdominios` | Enumeração de subdomínios por força bruta DNS com wordlist configurável |
| `portas` | Verificação das 20 portas mais comuns |
| `headers` | Coleta de headers HTTP reveladores (Server, X-Powered-By, CSP, etc.) |

- Relatório **JSON** para integração com outras ferramentas
- Relatório **HTML** com tema terminal para documentação de pentest
- Execução de módulos **individuais ou em conjunto**
- **Wordlist customizável** para enumeração de subdomínios
- Sem dependências externas — apenas biblioteca padrão do Python

---

## Uso

```bash
# Reconhecimento completo
python3 recon.py exemplo.com

# Módulos específicos
python3 recon.py exemplo.com --modulos dns whois geoip

# Com relatórios JSON e HTML
python3 recon.py exemplo.com --todos --json --html -o relatorio

# Wordlist customizada para subdomínios
python3 recon.py exemplo.com --modulos subdominios --wordlist wordlist.txt
```

### Opções

| Flag | Descrição | Padrão |
|------|-----------|--------|
| `--modulos` | Módulos a executar: `dns whois geoip subdominios portas headers` | todos |
| `--todos` | Executar todos os módulos | — |
| `--wordlist` | Arquivo de wordlist para subdomínios | wordlist interna (55 entradas) |
| `--json` | Salvar relatório JSON | desativado |
| `--html` | Salvar relatório HTML | desativado |
| `-o`, `--output` | Nome base do arquivo de saída | gerado automaticamente |

---

## Exemplo de Saída

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗
  ...
  Alvo   : scanme.nmap.org
  Módulos: dns, whois, geoip, subdominios, portas, headers

  ┌─ DNS ─────────────────────────────────────┐
  │  Registro A          45.33.32.156
  │  Registro MX         —
  │  Reverso (PTR)       45.33.32.156 → scanme.nmap.org
  └───────────────────────────────────────────┘

  ┌─ Geolocalização de IP ────────────────────┐
  │  IP                  45.33.32.156
  │  País                United States
  │  Estado              California
  │  Cidade              Fremont
  │  ISP                 Linode, LLC
  │  Coordenadas         37.5483, -121.9886
  └───────────────────────────────────────────┘

  ┌─ Portas Comuns (Top 20) ──────────────────┐
  │  [+] Porta 22     SSH
  │  [+] Porta 80     HTTP
  └───────────────────────────────────────────┘
```

---

## Estrutura do Projeto

```
recon-toolkit/
├── recon.py         # Ferramenta principal
├── wordlist.txt     # Wordlist customizada (opcional)
└── README.md        # Este arquivo
```

---

## Detalhes Técnicos

| Aspecto | Implementação |
|---------|--------------|
| DNS | `socket.getaddrinfo`, `socket.gethostbyaddr`, `nslookup` via subprocess |
| WHOIS | API pública `whoisjsonapi.com` + fallback via socket WHOIS direto |
| GeoIP | API pública `ip-api.com` |
| Subdomínios | Força bruta DNS com `ThreadPoolExecutor` (50 threads) |
| HTTP | `urllib.request` — sem dependências externas |
| Saída | JSON + HTML (tema terminal) |

---

## Conceitos Demonstrados

- Reconhecimento passivo e semi-passivo (OSINT)
- Enumeração de DNS e subdomínios
- Consumo de APIs REST públicas
- Multithreading com `concurrent.futures`
- Geração de relatórios estruturados
- Arquitetura modular com dispatch de funções

---

## Relação com o Fluxo de Pentest

```
[Recon Toolkit]  →  [Port Scanner]  →  Exploração
  Fase de             Fase de
  Reconhecimento      Descoberta
```

Este projeto cobre a **fase de reconhecimento** do framework PTES (Penetration Testing Execution Standard), coletando informações públicas antes de qualquer interação direta com o alvo.

---

## Aviso Legal

Esta ferramenta destina-se **exclusivamente a testes autorizados e fins educacionais**.
Realizar reconhecimento em sistemas sem permissão explícita pode ser ilegal.
O autor não se responsabiliza por uso indevido.

---

## Autor

**[Seu Nome]**
Pós-graduando em Ethical Hacking e Cibersegurança
[LinkedIn](https://linkedin.com/in/seuperfil) · [GitHub](https://github.com/seuusuario)
