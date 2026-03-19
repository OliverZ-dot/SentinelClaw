from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import capture_router, detector_router, arp_router, ai_router, attack_router, dashboard_router

app = FastAPI(
    title="SentinelAI - 智能网络威胁检测平台",
    version="1.0.0",
    description="融合 DeepSeek LLM 的新一代网络安全运营平台"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(capture_router.router, prefix="/api/capture", tags=["流量采集"])
app.include_router(detector_router.router, prefix="/api/detect", tags=["威胁检测"])
app.include_router(arp_router.router, prefix="/api/arp", tags=["ARP攻击"])
app.include_router(ai_router.router, prefix="/api/ai", tags=["AI分析"])
app.include_router(attack_router.router, prefix="/api/attack", tags=["攻击执行"])
app.include_router(dashboard_router.router, prefix="/api/dashboard", tags=["态势大屏"])


@app.get("/")
def root():
    return {"message": "SentinelAI 平台运行中", "status": "online"}
