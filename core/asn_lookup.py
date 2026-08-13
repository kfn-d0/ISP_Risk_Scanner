import httpx
import logging
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type

logger = logging.getLogger(__name__)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=False
)
async def get_asn_prefixes(asn: str) -> list[str]:
    asn_number = asn.upper().replace("AS", "")
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_number}"
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 ISP-Risk-Scanner/1.0"}
        async with httpx.AsyncClient(headers=headers, timeout=10) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            prefixes = []
            for item in data.get("data", {}).get("prefixes", []):
                prefix = item.get("prefix")
                if ":" not in prefix:
                    prefixes.append(prefix)
            return prefixes
    except httpx.HTTPStatusError as e:
        logger.error(f"[ASN Lookup] Erro de status HTTP para AS{asn_number}: {e}")
        return []
    except httpx.RequestError as e:
        logger.error(f"[ASN Lookup] Erro de conexão ao buscar prefixos para AS{asn_number}: {e}")
        return []
    except Exception as e:
        logger.error(f"[ASN Lookup] Erro inesperado para AS{asn_number}: {e}")
        return []

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    reraise=False
)
async def get_asn_info(asn: str) -> dict:
    asn_number = asn.upper().replace("AS", "")
    url = f"https://stat.ripe.net/data/as-overview/data.json?resource={asn_number}"
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 ISP-Risk-Scanner/1.0"}
        async with httpx.AsyncClient(headers=headers, timeout=10) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            holder = data.get("data", {}).get("holder", "Desconhecido")
            return {"asn": f"AS{asn_number}", "holder": holder}
    except Exception as e:
        logger.error(f"[ASN Info] Erro ao buscar informações do AS{asn_number}: {e}")
        return {"asn": f"AS{asn_number}", "holder": "Desconhecido"}
