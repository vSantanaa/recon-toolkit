#!/usr/bin/env python3
"""
ReconToolkit - Automação de Reconhecimento Passivo e Semi-Passivo
Autor: [Seu Nome]
Descrição: Coleta de informações de um alvo via WHOIS, DNS, subdomínios,
           geolocalização de IP e verificação de portas comuns.
Uso: python3 recon.py -h

AVISO LEGAL: Apenas para fins educacionais e testes autorizados.
"""

import socket
import argparse
import json
import sys
import os
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
import subprocess


# ─── Utilitários ──────────────────────────────────────────────────────────────

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

def banner():
    print(f"""{CYAN}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝
  {DIM}Reconhecimento Passivo e Semi-Passivo{RESET}
    """)

def section(title: str):
    print(f"\n{BOLD}{CYAN}  ┌─ {title} {'─' * (44 - len(title))}┐{RESET}")

def info(label: str, value: str):
    print(f"  {DIM}│{RESET}  {YELLOW}{label:<20}{RESET} {value}")

def success(msg: str):
    print(f"  {DIM}│{RESET}  {GREEN}[+]{RESET} {msg}")

def warn(msg: str):
    print(f"  {DIM}│{RESET}  {YELLOW}[!]{RESET} {msg}")

def error(msg: str):
    print(f"  {DIM}│{RESET}  {RED}[-]{RESET} {msg}")

def end_section():
    print(f"  {DIM}└{'─' * 47}┘{RESET}")

def http_get(url: str, timeout: int = 5) -> dict | None:
    """Faz uma requisição HTTP GET e retorna o JSON da resposta."""
    try:
        req = Request(url, headers={"User-Agent": "ReconToolkit/1.0"})
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


# ─── Módulos de reconhecimento ────────────────────────────────────────────────

def modulo_dns(target: str, results: dict):
    """Resolução DNS: A, MX, NS, TXT via socket e nslookup."""
    section("DNS")
    dns_data = {}

    # Registro A — IP principal
    try:
        ips = socket.getaddrinfo(target, None)
        unique_ips = list({r[4][0] for r in ips})
        dns_data["A"] = unique_ips
        for ip in unique_ips:
            info("Registro A", ip)
    except socket.gaierror:
        error(f"Não foi possível resolver {target}")
        dns_data["A"] = []

    # MX, NS, TXT via nslookup (cross-platform)
    for rtype in ["MX", "NS", "TXT"]:
        try:
            cmd = ["nslookup", f"-type={rtype}", target]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5)
            lines = out.decode(errors="replace").splitlines()
            records = [l.strip() for l in lines if rtype.lower() in l.lower()
                       and "=" in l]
            dns_data[rtype] = records
            if records:
                for r in records[:3]:
                    info(f"Registro {rtype}", r.split("=")[-1].strip()[:60])
            else:
                warn(f"Nenhum registro {rtype} encontrado")
        except Exception:
            warn(f"Não foi possível consultar {rtype}")
            dns_data[rtype] = []

    # Reverse DNS
    for ip in dns_data.get("A", [])[:2]:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            dns_data.setdefault("PTR", []).append(f"{ip} → {hostname}")
            info("Reverso (PTR)", f"{ip} → {hostname}")
        except Exception:
            pass

    end_section()
    results["dns"] = dns_data


def modulo_whois(target: str, results: dict):
    """WHOIS via API pública (whoisjsonapi.com)."""
    section("WHOIS")
    domain = target.replace("www.", "")
    data = http_get(f"https://whoisjsonapi.com/v1/{domain}")

    if not data:
        # fallback: tenta via socket WHOIS direto
        warn("API indisponível, tentando conexão direta...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(("whois.iana.org", 43))
                s.send(f"{domain}\r\n".encode())
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            whois_text = raw.decode(errors="replace")
            results["whois"] = {"raw": whois_text[:2000]}
            # Extrai campos básicos
            for line in whois_text.splitlines():
                for field in ["Registrar:", "Creation Date:", "Expiry Date:", "Name Server:"]:
                    if line.strip().startswith(field):
                        info(field.rstrip(":"), line.split(":", 1)[-1].strip()[:60])
        except Exception as e:
            error(f"WHOIS indisponível: {e}")
            results["whois"] = {}
        end_section()
        return

    whois = {}
    fields = {
        "domain_name":        "Domínio",
        "registrar":          "Registrar",
        "creation_date":      "Criado em",
        "expiration_date":    "Expira em",
        "updated_date":       "Atualizado em",
        "registrant_country": "País",
        "name_servers":       "Nameservers",
    }
    for key, label in fields.items():
        val = data.get(key) or data.get("domain", {}).get(key)
        if val:
            if isinstance(val, list):
                val = ", ".join(val[:3])
            info(label, str(val)[:70])
            whois[key] = val

    results["whois"] = whois
    end_section()


def modulo_geoip(target: str, results: dict):
    """Geolocalização de IP via ip-api.com."""
    section("Geolocalização de IP")

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        error("Não foi possível resolver o IP")
        results["geoip"] = {}
        end_section()
        return

    data = http_get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,query")

    if not data or data.get("status") != "success":
        error("Serviço de geolocalização indisponível")
        results["geoip"] = {"ip": ip}
        end_section()
        return

    geo = {
        "ip":      data.get("query", ip),
        "pais":    data.get("country", "—"),
        "estado":  data.get("regionName", "—"),
        "cidade":  data.get("city", "—"),
        "isp":     data.get("isp", "—"),
        "org":     data.get("org", "—"),
        "as":      data.get("as", "—"),
        "lat":     data.get("lat"),
        "lon":     data.get("lon"),
    }

    info("IP",       geo["ip"])
    info("País",     geo["pais"])
    info("Estado",   geo["estado"])
    info("Cidade",   geo["cidade"])
    info("ISP",      geo["isp"][:60])
    info("Org",      geo["org"][:60])
    info("AS",       geo["as"][:60])
    if geo["lat"] and geo["lon"]:
        info("Coordenadas", f"{geo['lat']}, {geo['lon']}")
        info("Maps",        f"https://maps.google.com/?q={geo['lat']},{geo['lon']}")

    results["geoip"] = geo
    end_section()


def modulo_subdominios(target: str, results: dict, wordlist: list[str]):
    """Enumeração de subdomínios por força bruta DNS."""
    section("Enumeração de Subdomínios")
    domain = target.replace("www.", "")
    found = []
    lock = threading.Lock()
    total = len(wordlist)
    done = 0

    def check(sub):
        nonlocal done
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            with lock:
                found.append({"subdomain": fqdn, "ip": ip})
                success(f"{fqdn:<40} {DIM}{ip}{RESET}")
        except socket.gaierror:
            pass
        finally:
            with lock:
                done += 1
                pct = int((done / total) * 30)
                bar = "█" * pct + "░" * (30 - pct)
                print(f"\r  │  [{bar}] {done}/{total}", end="", flush=True)

    with ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(check, wordlist))

    print()  # newline após progress bar

    if not found:
        warn("Nenhum subdomínio encontrado com a wordlist padrão")
    else:
        info("Total encontrados", str(len(found)))

    results["subdominios"] = found
    end_section()


def modulo_portas_comuns(target: str, results: dict):
    """Verifica as portas mais comuns (top 20)."""
    section("Portas Comuns (Top 20)")
    TOP20 = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
             3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017, 1433]
    SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
        27017: "MongoDB", 1433: "MSSQL",
    }

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        error("Não foi possível resolver o IP")
        results["portas"] = []
        end_section()
        return

    open_ports = []

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        for result in executor.map(check_port, TOP20):
            if result:
                svc = SERVICES.get(result, "?")
                open_ports.append({"port": result, "service": svc})
                success(f"Porta {result:<6} {GREEN}{svc}{RESET}")

    if not open_ports:
        warn("Nenhuma porta aberta nas top 20")
    else:
        info("Abertas", str(len(open_ports)))

    results["portas"] = open_ports
    end_section()


def modulo_headers_http(target: str, results: dict):
    """Coleta headers HTTP reveladores."""
    section("Headers HTTP")
    headers_data = {}

    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        try:
            req = Request(url, headers={"User-Agent": "ReconToolkit/1.0"}, method="HEAD")
            with urlopen(req, timeout=5) as r:
                interesting = [
                    "Server", "X-Powered-By", "X-AspNet-Version",
                    "X-Generator", "Via", "X-Frame-Options",
                    "Content-Security-Policy", "Strict-Transport-Security",
                    "X-Content-Type-Options", "Access-Control-Allow-Origin",
                ]
                for h in interesting:
                    val = r.headers.get(h)
                    if val:
                        info(h, val[:70])
                        headers_data[h] = val
                info("Status", f"{r.status} {r.reason}")
                headers_data["status"] = r.status
                break
        except Exception:
            continue

    if not headers_data:
        warn("Não foi possível obter headers HTTP")

    results["headers_http"] = headers_data
    end_section()


# ─── Geração de relatório ─────────────────────────────────────────────────────

def salvar_json(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n  {GREEN}[+]{RESET} Relatório JSON salvo → {path}")


def salvar_html(data: dict, path: str):
    target = data.get("alvo", "—")
    ts = data.get("timestamp", "—")

    def table_rows(d: dict) -> str:
        if not d:
            return "<tr><td colspan='2' class='empty'>Sem dados</td></tr>"
        rows = ""
        for k, v in d.items():
            if isinstance(v, list):
                v = "<br>".join(str(i) for i in v)
            rows += f"<tr><td class='key'>{k}</td><td>{str(v)[:200]}</td></tr>"
        return rows

    def port_rows(ports: list) -> str:
        if not ports:
            return "<tr><td colspan='2' class='empty'>Nenhuma porta aberta</td></tr>"
        return "".join(
            f"<tr><td>{p['port']}</td><td><span class='badge'>{p['service']}</span></td></tr>"
            for p in ports
        )

    def sub_rows(subs: list) -> str:
        if not subs:
            return "<tr><td colspan='2' class='empty'>Nenhum subdomínio encontrado</td></tr>"
        return "".join(
            f"<tr><td>{s['subdomain']}</td><td>{s['ip']}</td></tr>"
            for s in subs
        )

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Recon Report — {target}</title>
<style>
  :root {{
    --bg:#0d1117;--surface:#161b22;--border:#30363d;
    --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
    --green:#3fb950;--yellow:#d29922;--font:'Courier New',monospace;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:var(--font);padding:2rem;}}
  h1{{font-size:1.5rem;color:var(--accent);margin-bottom:.25rem}}
  .meta{{color:var(--muted);font-size:.8rem;margin-bottom:2rem}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.5rem;}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}}
  .card-title{{padding:.75rem 1rem;border-bottom:1px solid var(--border);
               font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}}
  table{{width:100%;border-collapse:collapse;font-size:.82rem}}
  td{{padding:.5rem 1rem;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-all}}
  td.key{{color:var(--muted);white-space:nowrap;width:35%}}
  td.empty{{color:var(--muted);text-align:center;padding:1rem}}
  .badge{{background:rgba(63,185,80,.15);color:var(--green);
          border:1px solid rgba(63,185,80,.3);border-radius:12px;
          padding:1px 8px;font-size:.75rem}}
</style>
</head>
<body>
  <h1>Recon Report — {target}</h1>
  <p class="meta">Gerado em: {ts}</p>
  <div class="grid">
    <div class="card">
      <div class="card-title">DNS</div>
      <table>{table_rows(data.get('dns', {}))}</table>
    </div>
    <div class="card">
      <div class="card-title">WHOIS</div>
      <table>{table_rows(data.get('whois', {}))}</table>
    </div>
    <div class="card">
      <div class="card-title">Geolocalização</div>
      <table>{table_rows(data.get('geoip', {}))}</table>
    </div>
    <div class="card">
      <div class="card-title">Headers HTTP</div>
      <table>{table_rows(data.get('headers_http', {}))}</table>
    </div>
    <div class="card">
      <div class="card-title">Portas Abertas</div>
      <table><tr><th style="text-align:left;padding:.5rem 1rem;color:var(--muted)">Porta</th>
      <th style="text-align:left;padding:.5rem 1rem;color:var(--muted)">Serviço</th></tr>
      {port_rows(data.get('portas', []))}</table>
    </div>
    <div class="card">
      <div class="card-title">Subdomínios</div>
      <table><tr><th style="text-align:left;padding:.5rem 1rem;color:var(--muted)">Subdomínio</th>
      <th style="text-align:left;padding:.5rem 1rem;color:var(--muted)">IP</th></tr>
      {sub_rows(data.get('subdominios', []))}</table>
    </div>
  </div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  {GREEN}[+]{RESET} Relatório HTML salvo → {path}")


# ─── Wordlist padrão para subdomínios ─────────────────────────────────────────

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "mx", "dev", "staging", "test", "admin", "api", "app", "portal",
    "vpn", "remote", "secure", "login", "m", "mobile", "blog", "shop",
    "store", "cdn", "static", "assets", "media", "img", "images",
    "files", "download", "upload", "support", "help", "docs", "wiki",
    "git", "gitlab", "jenkins", "jira", "confluence", "ldap", "intranet",
    "internal", "corp", "backup", "db", "mysql", "sql", "redis", "mongo",
]


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="ReconToolkit — Reconhecimento passivo e semi-passivo",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
exemplos:
  python3 recon.py exemplo.com
  python3 recon.py exemplo.com --modulos dns whois geoip
  python3 recon.py exemplo.com --todos --html --json -o relatorio
  python3 recon.py exemplo.com --wordlist minha_lista.txt

aviso:
  Apenas para testes autorizados. Reconhecimento não autorizado pode ser ilegal.
        """,
    )
    parser.add_argument("target", help="Domínio ou IP alvo (ex: exemplo.com)")
    parser.add_argument(
        "--modulos", nargs="+",
        choices=["dns", "whois", "geoip", "subdominios", "portas", "headers"],
        help="Módulos a executar (padrão: todos)",
    )
    parser.add_argument("--todos", action="store_true",
                        help="Executar todos os módulos")
    parser.add_argument("--wordlist", help="Arquivo de wordlist para subdomínios")
    parser.add_argument("--json", action="store_true", help="Salvar relatório JSON")
    parser.add_argument("--html", action="store_true", help="Salvar relatório HTML")
    parser.add_argument("-o", "--output", help="Nome base do arquivo de saída")

    args = parser.parse_args()
    banner()

    modulos = args.modulos or ["dns", "whois", "geoip", "subdominios", "portas", "headers"]

    wordlist = DEFAULT_WORDLIST
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [l.strip() for l in f if l.strip()]
            print(f"  {GREEN}[+]{RESET} Wordlist carregada: {len(wordlist)} entradas\n")
        except FileNotFoundError:
            print(f"  {YELLOW}[!]{RESET} Wordlist não encontrada, usando padrão\n")

    print(f"  {BOLD}Alvo:{RESET} {args.target}")
    print(f"  {BOLD}Módulos:{RESET} {', '.join(modulos)}")
    print(f"  {BOLD}Início:{RESET} {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    results = {
        "alvo": args.target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    dispatch = {
        "dns":        lambda: modulo_dns(args.target, results),
        "whois":      lambda: modulo_whois(args.target, results),
        "geoip":      lambda: modulo_geoip(args.target, results),
        "subdominios":lambda: modulo_subdominios(args.target, results, wordlist),
        "portas":     lambda: modulo_portas_comuns(args.target, results),
        "headers":    lambda: modulo_headers_http(args.target, results),
    }

    for mod in modulos:
        dispatch[mod]()

    base = args.output or f"recon_{args.target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    if args.json:
        salvar_json(results, f"{base}.json")
    if args.html:
        salvar_html(results, f"{base}.html")

    print(f"\n  {BOLD}{GREEN}Reconhecimento concluído.{RESET}\n")


if __name__ == "__main__":
    main()
