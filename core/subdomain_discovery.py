import httpx
import logging
import re
from typing import Set
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type

logger = logging.getLogger(__name__)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
    reraise=False
)
async def discover_subdomains(domain: str) -> Set[str]:
    """
    Realiza a descoberta passiva de subdomínios usando logs de transparência de certificados (crt.sh).
    """
    if not domain or len(domain) < 4:
        return set()

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 ISP-Risk-Scanner/1.0"}
        async with httpx.AsyncClient(headers=headers, timeout=15) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    # crt.sh pode retornar múltiplos nomes separados por \n
                    for name in name_value.split("\n"):
                        clean_name = name.strip().lower()
                        if clean_name.endswith(domain) and "*" not in clean_name:
                            subdomains.add(clean_name)
            
    except Exception as e:
        logger.error(f"[Subdomain Discovery] Erro ao consultar crt.sh para {domain}: {e}")
        
    return subdomains

def extract_main_domain(holder_name: str) -> str:
    """
    Tenta extrair um domínio provável do nome do holder.
    Esta é uma heurística simples; em um ambiente real, poderíamos usar WHOIS.
    """
    # Remove termos comuns de empresas
    clean = holder_name.lower()
    for term in ["ltda", "s.a.", "sa", "eireli", "me", "servicos", "internet", "telecom", "comunicacoes", "-", ".", ","]:
        clean = clean.replace(term, " ")
    
    parts = clean.split()
    if not parts:
        return ""
        
    # Pega a parte mais significativa (geralmente a primeira palavra longa)
    candidate = ""
    for p in parts:
        if len(p) > 3:
            candidate = p
            break
            
    if not candidate:
        candidate = parts[0]
        
    # Retorna uma suposição de domínio (muitos ISPs brasileiros usam .net.br ou .com.br)
    return f"{candidate}.net.br"
