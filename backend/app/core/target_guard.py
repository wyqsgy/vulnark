"""扫描目标授权范围校验（白名单）。

防止平台被滥用为攻击跳板：公网部署时应设置 ALLOWED_SCAN_TARGETS，
仅允许对授权范围内的目标发起验证。
"""

from __future__ import annotations

import fnmatch
import ipaddress
from urllib.parse import urlparse


def _extract_host(target: str) -> str:
    """从 URL / host:port / 裸域名中提取主机名。"""
    target = (target or "").strip()
    if "://" not in target:
        target = "http://" + target
    host = urlparse(target).hostname
    return (host or "").strip().lower().rstrip(".")


def validate_scan_target(target: str, allowlist: list[str] | None = None) -> bool:
    """校验目标是否在授权范围内。

    allowlist 为空列表/None 时不限制（返回 True）。
    条目支持：
    - CIDR 网段：10.0.0.0/8, 192.168.1.0/24
    - 精确 IP：10.0.0.5
    - 精确域名：example.com（同时放行其子域）
    - 通配符域名：*.example.com
    """
    if allowlist is None:
        from app.config import ALLOWED_SCAN_TARGETS
        allowlist = ALLOWED_SCAN_TARGETS

    if not allowlist:
        return True

    host = _extract_host(target)
    if not host:
        return False

    # 尝试按 IP/CIDR 匹配
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        for entry in allowlist:
            entry = entry.strip()
            if "/" in entry:
                try:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if ipaddress.ip_address(entry) == ip:
                        return True
                except ValueError:
                    pass
                # 域名条目兜底匹配字符串（IP 不会等于域名，忽略）
        return False

    # 域名匹配：精确 / 子域后缀 / 通配符
    for entry in allowlist:
        e = entry.strip().lower().rstrip(".")
        if "*" in e:
            if fnmatch.fnmatch(host, e):
                return True
        elif host == e or host.endswith("." + e):
            return True
    return False
