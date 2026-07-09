from sqlalchemy.orm import Session
from models import Asset
from datetime import datetime, timezone
import logging

logger = logging.getLogger("tempris.seeder")

def seed_assets(db: Session):
    """Seed the database with realistic production assets if empty."""
    if db.query(Asset).count() > 0:
        return  # Already seeded

    logger.info("Seeding production assets...")
    
    initial_assets = [
        {
            "id": "ASSET-0001",
            "name": "Fortinet Perimeter Edge Firewall",
            "asset_type": "network",
            "ip_address": "10.0.5.1",
            "hostname": "fw-edge-01.tempris.local",
            "criticality": "critical",
            "owner": "Network Engineering",
            "environment": "production",
            "tags": ["perimeter", "firewall", "fortinet", "fortios"],
            "notes": "Main ingress/egress firewall for SG datacenter."
        },
        {
            "id": "ASSET-0002",
            "name": "Cisco Core Switch 9000",
            "asset_type": "network",
            "ip_address": "10.0.1.1",
            "hostname": "sw-core-01.tempris.local",
            "criticality": "critical",
            "owner": "Network Engineering",
            "environment": "production",
            "tags": ["core", "switch", "cisco", "ios_xe"],
            "notes": "Datacenter core routing."
        },
        {
            "id": "ASSET-0003",
            "name": "Microsoft Windows Server 2022 - DC",
            "asset_type": "server",
            "ip_address": "10.0.10.10",
            "hostname": "dc-01.tempris.local",
            "criticality": "critical",
            "owner": "IT Identity",
            "environment": "production",
            "tags": ["windows", "activedirectory", "microsoft", "domain_controller"],
            "notes": "Primary Active Directory Domain Controller."
        },
        {
            "id": "ASSET-0004",
            "name": "Microsoft Exchange Server 2019",
            "asset_type": "server",
            "ip_address": "10.0.10.15",
            "hostname": "mail-01.tempris.local",
            "criticality": "high",
            "owner": "IT Infrastructure",
            "environment": "production",
            "tags": ["windows", "exchange", "microsoft", "email"],
            "notes": "On-premise Exchange server for legacy services."
        },
        {
            "id": "ASSET-0005",
            "name": "Ivanti Connect Secure VPN",
            "asset_type": "network",
            "ip_address": "10.0.5.5",
            "hostname": "vpn.tempris.com",
            "criticality": "critical",
            "owner": "Network Security",
            "environment": "production",
            "tags": ["vpn", "ivanti", "connect_secure", "remote_access"],
            "notes": "Employee remote access gateway."
        },
        {
            "id": "ASSET-0006",
            "name": "Atlassian Confluence Server",
            "asset_type": "application",
            "ip_address": "10.0.20.50",
            "hostname": "wiki.tempris.local",
            "criticality": "medium",
            "owner": "Engineering",
            "environment": "production",
            "tags": ["atlassian", "confluence", "wiki", "internal"],
            "notes": "Internal engineering documentation."
        },
        {
            "id": "ASSET-0007",
            "name": "Oracle Database 19c",
            "asset_type": "database",
            "ip_address": "10.0.30.100",
            "hostname": "db-fin-01.tempris.local",
            "criticality": "critical",
            "owner": "DBA Team",
            "environment": "production",
            "tags": ["database", "oracle", "financial", "pci"],
            "notes": "Main financial ledger database."
        },
        {
            "id": "ASSET-0008",
            "name": "Palo Alto Networks PAN-OS Firewall",
            "asset_type": "network",
            "ip_address": "10.0.5.2",
            "hostname": "fw-palo-01.tempris.local",
            "criticality": "high",
            "owner": "Network Engineering",
            "environment": "staging",
            "tags": ["firewall", "palo_alto_networks", "pan-os"],
            "notes": "Staging environment firewall."
        },
        {
            "id": "ASSET-0009",
            "name": "Citrix NetScaler ADC",
            "asset_type": "network",
            "ip_address": "10.0.5.10",
            "hostname": "lb-01.tempris.local",
            "criticality": "high",
            "owner": "Network Engineering",
            "environment": "production",
            "tags": ["load_balancer", "citrix", "netscaler", "adc"],
            "notes": "Web application load balancer."
        },
        {
            "id": "ASSET-0010",
            "name": "Ubuntu 22.04 LTS Web Host",
            "asset_type": "server",
            "ip_address": "10.0.20.10",
            "hostname": "web-01.tempris.local",
            "criticality": "medium",
            "owner": "Web Team",
            "environment": "production",
            "tags": ["linux", "ubuntu", "nginx", "canonical"],
            "notes": "Corporate website hosting."
        }
    ]

    for data in initial_assets:
        asset = Asset(
            id=data["id"],
            name=data["name"],
            asset_type=data["asset_type"],
            ip_address=data["ip_address"],
            hostname=data["hostname"],
            criticality=data["criticality"],
            owner=data["owner"],
            environment=data["environment"],
            tags=data["tags"],
            notes=data["notes"],
            status="active",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.add(asset)
    
    db.commit()
    logger.info(f"Seeded {len(initial_assets)} assets.")
