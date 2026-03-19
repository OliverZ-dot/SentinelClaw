from fastapi import APIRouter
from fastapi.responses import Response
from pydantic import BaseModel
from core.arp_forge import (
    build_arp_spoof_packets,
    build_arp_flood_packets,
    build_arp_scan_packets,
    build_gratuitous_arp_packets,
    build_mitm_arp_packets,
    get_pcap_bytes,
)

router = APIRouter()


class ARPSpoofRequest(BaseModel):
    target_ip: str
    target_mac: str
    spoof_ip: str
    attacker_mac: str = "aa:bb:cc:dd:ee:ff"


class ARPFloodRequest(BaseModel):
    count: int = 100
    src_ip_base: str = "192.168.1"


class ARPScanRequest(BaseModel):
    network: str = "192.168.1"
    start: int = 1
    end: int = 50


class GratuitousARPRequest(BaseModel):
    ip: str
    mac: str
    count: int = 10


class MITMRequest(BaseModel):
    victim1_ip: str
    victim1_mac: str
    victim2_ip: str
    victim2_mac: str


@router.post("/spoof/download")
def download_arp_spoof(req: ARPSpoofRequest):
    pkts = build_arp_spoof_packets(req.target_ip, req.target_mac, req.spoof_ip, req.attacker_mac)
    data = get_pcap_bytes(pkts)
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=arp_spoof.pcap"}
    )


@router.post("/flood/preview")
def preview_arp_flood(req: ARPFloodRequest):
    pkts = build_arp_flood_packets("lo", req.count, req.src_ip_base)
    return {"constructed_count": len(pkts), "sample": str(pkts[0].summary()) if pkts else ""}


@router.post("/scan/preview")
def preview_arp_scan(req: ARPScanRequest):
    pkts = build_arp_scan_packets(req.network, req.start, req.end)
    return {"constructed_count": len(pkts), "target_range": f"{req.network}.{req.start}-{req.end}"}


@router.post("/gratuitous/preview")
def preview_gratuitous(req: GratuitousARPRequest):
    pkts = build_gratuitous_arp_packets(req.ip, req.mac, req.count)
    return {"constructed_count": len(pkts), "type": "Gratuitous ARP Abuse"}


@router.post("/mitm/preview")
def preview_mitm(req: MITMRequest):
    result = build_mitm_arp_packets(
        req.victim1_ip, req.victim1_mac,
        req.victim2_ip, req.victim2_mac
    )
    return {
        "description": result["description"],
        "packet_to_victim1": result["to_victim1"].summary(),
        "packet_to_victim2": result["to_victim2"].summary(),
    }
