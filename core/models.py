from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class ExposureItem(BaseModel):
    ip: str
    port: int
    service: str
    banner: str
    prefix: str
    simulated: bool
    vulns_count: int
    has_otx: bool
    risk_level: str
    score: int

class Metrics(BaseModel):
    total_time_seconds: float
    total_exposures: int
    total_ips: int
    total_score: int
    avg_score_per_prefix: float

class PrefixScore(BaseModel):
    prefix: str
    score: int

class ServiceCount(BaseModel):
    service: str
    count: int

class AsnInfo(BaseModel):
    asn: str
    holder: str

class GoogleDork(BaseModel):
    category: str
    title: str
    dork: str
    url: str

class ScanResult(BaseModel):
    asn: str
    metrics: Metrics
    port_distribution: Dict[str, int]
    top_prefixes: List[PrefixScore]
    top_services: List[ServiceCount]
    raw_data: List[ExposureItem]
    asn_info: Optional[AsnInfo] = None
    google_dorks: Optional[List[GoogleDork]] = None
    subdomains: Optional[List[str]] = None
    domain_guess: Optional[str] = None
