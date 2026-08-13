import time
import os
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field, field_validator
import uvicorn
import re
import logging
import io
import csv

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from core.asn_lookup import get_asn_prefixes, get_asn_info
from core.passive_collector import collect_passive_data
from core.risk_engine import calculate_risk
from core.db import init_db, save_scan, get_latest_scans
from core.dork_generator import generate_google_dorks
from core.subdomain_discovery import discover_subdomains, extract_main_domain
from core.models import ScanResult

from contextlib import asynccontextmanager

def is_docker():
    path = '/proc/self/cgroup'
    return (
        os.path.exists('/.dockerenv') or
        os.path.isfile(path) and any('docker' in line for line in open(path))
    )

RUNNING_IN_DOCKER = is_docker()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="ISP Risk Exposure Scanner", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")

class AnalyzeRequest(BaseModel):
    asn: str = Field(..., description="ASN a ser analisado (ex: AS12345 ou 12345)")

    @field_validator('asn')
    @classmethod
    def validate_asn(cls, v: str) -> str:
        v = v.strip().upper()
        if not re.match(r'^(AS)?\d+$', v):
            raise ValueError("ASN deve conter apenas números, opcionalmente prefixados por 'AS'.")
        if not v.startswith("AS"):
            v = f"AS{v}"
        return v

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return FileResponse("static/index.html")

@app.get("/api/env")
async def get_env_info():
    return {"is_docker": RUNNING_IN_DOCKER}

@app.websocket("/api/ws/analyze")
async def websocket_analyze(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        asn = data.get("asn", "").strip().upper()
        
        if not asn:
            await websocket.send_json({"type": "error", "message": "ASN é obrigatório."})
            return
            
        if not re.match(r'^(AS)?\d+$', asn):
            await websocket.send_json({"type": "error", "message": "Formato de ASN inválido."})
            return

        if not asn.startswith("AS"):
            asn = f"AS{asn}"
            
        start_time = time.time()
        await websocket.send_json({"type": "status", "message": f"[*] Iniciando análise para o {asn}..."})
        
        # 1. ASN Info & Dorks & Subdomains
        asn_info = await get_asn_info(asn)
        holder = asn_info.get("holder", "Desconhecido")
        dorks = generate_google_dorks(holder)
        
        domain_guess = extract_main_domain(holder)
        await websocket.send_json({"type": "status", "message": f"[*] Identificado: {holder}. Buscando subdomínios via Cert-Transparency..."})
        subdomains = await discover_subdomains(domain_guess)
        await websocket.send_json({"type": "status", "message": f"[*] Descobertos {len(subdomains)} subdomínios associados a {domain_guess}."})

        # 2. Prefixes
        prefixes = await get_asn_prefixes(asn)
        await websocket.send_json({"type": "status", "message": f"[*] Descobertos {len(prefixes)} blocos IPv4 associados."})
        
        async def progress_cb(msg: str):
            await websocket.send_json({"type": "status", "message": msg})
            
        collected_data = await collect_passive_data(prefixes, asn, progress_cb)
        await websocket.send_json({"type": "status", "message": f"[*] Coletadas {len(collected_data)} exposições possíveis. Finalizando cálculos..."})
        
        end_time = time.time()
        total_time = end_time - start_time
        
        results = calculate_risk(collected_data, asn, total_time, len(subdomains))
        results["asn_info"] = asn_info
        results["google_dorks"] = dorks
        results["subdomains"] = list(subdomains)
        results["domain_guess"] = domain_guess
        
        await asyncio.to_thread(save_scan, asn, results["metrics"]["total_ips"], results["metrics"]["total_score"], results)
        
        await websocket.send_json({"type": "complete", "data": results})
        
    except WebSocketDisconnect:
        logger.info("Cliente desconectado")
    except Exception as e:
        logger.error(f"Erro no WebSocket: {e}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass

@app.post("/api/analyze", response_model=ScanResult)
async def analyze_asn(req: AnalyzeRequest):
    start_time = time.time()
    asn = req.asn
    prefixes = await get_asn_prefixes(asn)
    collected_data = await collect_passive_data(prefixes, asn)
    end_time = time.time()
    total_time = end_time - start_time
    results = calculate_risk(collected_data, asn, total_time)
    await asyncio.to_thread(save_scan, asn, results["metrics"]["total_ips"], results["metrics"]["total_score"], results)
    return results

@app.get("/api/export/json/{asn}")
async def export_json(asn: str):
    scans = await asyncio.to_thread(get_latest_scans, asn, 1)
    if not scans:
        return JSONResponse(status_code=404, content={"message": "No scans found for this ASN"})
    return JSONResponse(content=scans[0])

@app.get("/api/export/csv/{asn}")
async def export_csv(asn: str):
    scans = await asyncio.to_thread(get_latest_scans, asn, 1)
    if not scans:
        return JSONResponse(status_code=404, content={"message": "No scans found for this ASN"})

    data = scans[0]
    raw_data = data.get("raw_data", [])

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["IP", "Prefix", "Port", "Service", "Risk Level", "Banner"])

    for item in raw_data:
        writer.writerow([
            item.get("ip", ""),
            item.get("prefix", ""),
            item.get("port", ""),
            item.get("service", ""),
            item.get("risk_level", ""),
            item.get("banner", "")
        ])

    csv_string = output.getvalue()

    return Response(
        content=csv_string,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan_{asn}.csv"}
    )

@app.get("/api/diff/{asn}")
async def diff_scans(asn: str):
    scans = await asyncio.to_thread(get_latest_scans, asn, 2)
    if len(scans) < 2:
        return JSONResponse(status_code=400, content={"message": "Not enough historical scans to compute diff (requires at least 2)."})

    latest_scan = scans[0]
    previous_scan = scans[1]

    latest_exposures = {f"{item.get('ip')}:{item.get('port')}": item for item in latest_scan.get("raw_data", [])}
    previous_exposures = {f"{item.get('ip')}:{item.get('port')}": item for item in previous_scan.get("raw_data", [])}

    new_exposures = []
    for key, item in latest_exposures.items():
        if key not in previous_exposures:
            new_exposures.append(item)

    return JSONResponse(content={
        "new_exposures_count": len(new_exposures),
        "new_exposures": new_exposures
    })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
