import os
import httpx
import random
import ipaddress
import asyncio
import logging
from typing import Callable, Any
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type

logger = logging.getLogger(__name__)

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 
    443: "HTTPS", 445: "SMB", 500: "(IKE) VPN (IPsec)", 1433: "MSSQL",
    1701: "L2TP", 1723: "PPTP", 2000: "MIKROTIK_BTEST", 3306: "MySQL",
    3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 7547: "CWMP|TR-069",
    8080: "HTTP Proxy", 8291: "Winbox (Mikrotik)", 
    8443: "HTTPS (Alt)", 45666: "HTTP", 161: "SNMP"
}

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
async def get_alienvault_intel(client: httpx.AsyncClient, ip_str: str) -> str:
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_str}/general"
        resp = await client.get(url, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            if pulses > 0:
                return f"[OTX: {pulses} alertas de ameaça(Malware/Spam)]"
    except httpx.RequestError as e:
        logger.debug(f"Falha na consulta OTX para {ip_str}: {e}")
    except Exception as e:
        logger.warning(f"Erro inesperado no OTX para {ip_str}: {e}")
    return ""

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
async def _do_scan_single_ip(client: httpx.AsyncClient, ip_str: str, prefix: str) -> list[dict]:
    local_results = []
    try:
        url = f"https://internetdb.shodan.io/{ip_str}"
        resp = await client.get(url, timeout=6)

        if resp.status_code == 200:
            data = resp.json()
            ports = data.get("ports", [])
            hostnames = data.get("hostnames", [])
            cpes = data.get("cpes", [])
            vulns = data.get("vulns", [])
            
            if ports:
                otx_intel = await get_alienvault_intel(client, ip_str)
                
                detalhes = []
                if hostnames: detalhes.append(f"Host: {hostnames[0]}")
                if cpes: detalhes.append(f"CPEs: {', '.join(cpes[:2])}")
                if vulns: detalhes.append(f"CVEs: {len(vulns)}")
                if otx_intel: detalhes.append(otx_intel)

                banner_str = " | ".join(detalhes) if detalhes else "Status Ativo Confirmado (Desconhecido)"

                for port in ports:
                    service_name = KNOWN_SERVICES.get(port)
                    service_format = f"{port} ({service_name})" if service_name else str(port)
                    local_results.append({
                        "ip": data.get("ip"),
                        "port": port,
                        "service": service_format,
                        "banner": banner_str[:120],
                        "prefix": prefix,
                        "simulated": False,
                        "vulns_count": len(vulns),
                        "has_otx": bool(otx_intel)
                    })
    except httpx.TimeoutException:
        logger.debug(f"Timeout na varredura do IP {ip_str}")
        raise
    except httpx.RequestError as e:
        logger.debug(f"Falha de rede na varredura do IP {ip_str}: {e}")
        raise
    except Exception as e:
        logger.error(f"Erro inesperado na varredura do IP {ip_str}: {e}")
    return local_results

async def scan_single_ip(client: httpx.AsyncClient, semaphore: asyncio.Semaphore, ip_str: str, prefix: str) -> list[dict]:
    async with semaphore:
        try:
            return await _do_scan_single_ip(client, ip_str, prefix)
        except Exception:
            return []

async def query_shodan_asn(client: httpx.AsyncClient, asn: str, api_key: str, progress_callback: Callable = None) -> list[dict]:
    results = []
    page = 1
    total_found = 0
    asn_query = asn if asn.upper().startswith("AS") else f"AS{asn}"
    try:
        while True:
            if progress_callback:
                await progress_callback(f"[Pass Col] Buscando página {page} na Shodan API para {asn_query}...")
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=asn:{asn_query}&page={page}"
            resp = await client.get(url, timeout=10)
            if resp.status_code != 200:
                break
            
            data = resp.json()
            matches = data.get("matches", [])
            if not matches:
                break
            
            for m in matches:
                ip = m.get("ip_str")
                port = m.get("port")
                vulns = m.get("vulns", {})
                hostnames = m.get("hostnames", [])
                
                detalhes = []
                if hostnames: detalhes.append(f"Host: {hostnames[0]}")
                if vulns: detalhes.append(f"CVEs: {len(vulns)}")
                
                service_name = KNOWN_SERVICES.get(port)
                service_format = f"{port} ({service_name})" if service_name else str(port)
                
                results.append({
                    "ip": ip,
                    "port": port,
                    "service": service_format,
                    "banner": " | ".join(detalhes) if detalhes else "Shodan API Discovery",
                    "prefix": "Descoberto via ASN search",
                    "simulated": False,
                    "vulns_count": len(vulns),
                    "has_otx": False
                })
            
            total_found += len(matches)
            page += 1
            if page > 5:
                break
    except Exception as e:
        if progress_callback:
            await progress_callback(f"[Erro Shodan] {e}")
    return results

async def collect_passive_data(prefixes: list[str], asn: str = None, progress_callback: Callable = None) -> list[dict]:
    results = []
    shodan_key = os.getenv("SHODAN_API_KEY", "").strip()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 ISP-Risk-Scanner/1.0"}
    
    async with httpx.AsyncClient(headers=headers, limits=httpx.Limits(max_connections=50, max_keepalive_connections=20)) as client:
        if shodan_key and asn:
            if progress_callback:
                await progress_callback("[Pass Col] Chave de API Shodan detectada. Usando pesquisa global por ASN (Modo Avançado)...")
            results = await query_shodan_asn(client, asn, shodan_key, progress_callback)
            if results:
                if progress_callback:
                    await progress_callback(f"[Pass Col] Varredura global concluída. Encontrados: {len(results)} exposições reais via API.")
                return results
            if progress_callback:
                await progress_callback("[Pass Col] Nenhuma exposição na consulta global. Iniciando Fallback via InternetDB...")

        if progress_callback:
            await progress_callback("[Pass Col] Usando Shodan InternetDB + AlienVault OTX (Modo Assíncrono Nativo)...")
            
        target_ips = []
        for prefix in prefixes[:50]: 
            try:
                net = ipaddress.ip_network(prefix)
                if net.prefixlen >= 31:
                    for ip in net:
                        target_ips.append((str(ip), prefix))
                    continue

                num_hosts = net.num_addresses - 2
                if num_hosts > 0:
                    indices = set()
                    for i in range(1, min(6, num_hosts + 1)):
                        indices.add(i)
                    for i in range(max(1, num_hosts - 2), num_hosts + 1):
                        indices.add(i)
                    min_mid = 6
                    max_mid = num_hosts - 3
                    if max_mid >= min_mid:
                        samples = min(10, max_mid - min_mid + 1)
                        for r_idx in random.sample(range(min_mid, max_mid + 1), samples):
                            indices.add(r_idx)
                    for idx in indices:
                        target_ips.append((str(net[idx]), prefix))
            except (ValueError, IndexError) as e:
                logger.warning(f"Erro ao processar prefixo {prefix}: {e}")
                continue
            except Exception as e:
                logger.error(f"Erro inesperado ao processar prefixo {prefix}: {e}")
                continue
                
        if progress_callback:
            await progress_callback(f"[Pass Col] Disparando consultas assíncronas concorrentes para {len(target_ips)} IPs...")

        semaphore = asyncio.Semaphore(30)
        tasks = [scan_single_ip(client, semaphore, ip, pref) for ip, pref in target_ips]
        completed = 0
        total = len(tasks)
        for task in asyncio.as_completed(tasks):
            res = await task
            if res:
                results.extend(res)
            completed += 1
            if completed % 20 == 0 and progress_callback:
                await progress_callback(f"[Pass Col] IP's mapeados: {completed}/{total} concluídos...")
                
    if progress_callback:
        await progress_callback(f"[Pass Col] Varredura assíncrona concluída. Encontrados: {len(results)} exposições reais.")
    return results

def generate_mock_data(prefixes: list[str]) -> list[dict]:
    return []
