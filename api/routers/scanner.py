from fastapi import APIRouter
from pydantic import BaseModel
import asyncio
import socket

router = APIRouter()

class ScanTarget(BaseModel):
    target: str

async def check_port(host: str, port: int) -> dict | None:
    try:
        # Strip http:// or https:// for port scanning
        host_clean = host.replace("http://", "").replace("https://", "").split("/")[0]
        if ":" in host_clean:
            host_clean = host_clean.split(":")[0]
            
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host_clean, port), timeout=1.5
        )
        writer.close()
        await writer.wait_closed()
        return {"port": port, "state": "open"}
    except Exception:
        return None

@router.post("/scan")
async def trigger_scan(target: ScanTarget):
    """Trigger an active port scan against the target."""
    try:
        common_ports = [21, 22, 23, 80, 443, 8080, 3306, 5432, 27017]
        tasks = [check_port(target.target, port) for port in common_ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None]
        
        message = f"Scan completed. Discovered {len(open_ports)} open ports on {target.target}."
        
        # We could also seed these findings into the DB, but for MVP we return them.
        return {"status": "success", "findings": len(open_ports), "open_ports": open_ports, "message": message}
        
    except Exception as e:
        print(f"Active Scan Error: {e}")
        return {"status": "error", "message": str(e)}
