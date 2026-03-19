"""
攻击执行记录：存储每次攻击模拟/真实发包的日志
"""
import time
from datetime import datetime
from typing import List, Dict, Any

_attack_logs: List[Dict[str, Any]] = []
_MAX_LOGS = 500


def append_log(record: Dict[str, Any]) -> Dict[str, Any]:
    """追加一条攻击记录，返回带 id 的完整记录"""
    global _attack_logs
    record["id"] = f"atk_{int(time.time() * 1000)}"
    record["finished_at"] = datetime.now().isoformat()
    _attack_logs.append(record)
    if len(_attack_logs) > _MAX_LOGS:
        _attack_logs = _attack_logs[-_MAX_LOGS:]
    return record


def get_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """获取最近 limit 条攻击记录，按时间倒序"""
    return list(reversed(_attack_logs[-limit:]))
