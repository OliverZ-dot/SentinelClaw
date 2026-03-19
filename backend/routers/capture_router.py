from fastapi import APIRouter, UploadFile, File, HTTPException
import tempfile
import os
from core.capture import analyze_pcap, capture_live

router = APIRouter()


@router.post("/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    """上传并解析 PCAP 文件"""
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="仅支持 .pcap / .pcapng 文件")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name
    try:
        records = analyze_pcap(tmp_path)
        return {"total": len(records), "packets": records[:500]}
    finally:
        os.unlink(tmp_path)


@router.get("/live")
async def live_capture(interface: str = "eth0", duration: int = 5):
    """实时抓包（需 sudo）"""
    try:
        records = await capture_live(interface, duration)
        return {"total": len(records), "packets": records}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"抓包失败（可能需要 sudo）: {str(e)}")
