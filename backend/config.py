import os
from pathlib import Path
from pydantic_settings import BaseSettings

_env_path = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    """DeepSeek/OpenAI 兼容 API 请求超时（秒），连不上网时可适当调大或检查代理"""
    deepseek_timeout: int = 90
    """HTTP/HTTPS 代理，为空时使用环境变量 HTTP_PROXY/HTTPS_PROXY。示例: http://127.0.0.1:7890"""
    http_proxy: str = ""
    """网页检索（DuckDuckGo）超时（秒），国内网络可配合 http_proxy 使用"""
    search_timeout: int = 25
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000

    class Config:
        env_file = _env_path
        extra = "ignore"

    def get_effective_proxy(self) -> str | None:
        """优先使用配置的 http_proxy，否则读环境变量"""
        if self.http_proxy:
            return self.http_proxy.strip()
        return os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or None


settings = Settings()
