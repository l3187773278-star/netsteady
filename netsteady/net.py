"""最底层的网络原语：TCP 握手、HTTP、DNS.

全部基于标准库，不引入第三方依赖。
"""

from __future__ import annotations

import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import __version__

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 netsteady/%s" % __version__
)


@dataclass
class HttpResponse:
    """一次 HTTP 请求的结果.

    注意 ok 只表示"拿到了 HTTP 响应"（含 4xx/5xx），
    不代表状态码是 2xx。
    """

    ok: bool
    status: Optional[int]
    body: str
    elapsed_ms: float
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)

    def json(self):  # noqa: A003
        import json

        try:
            return json.loads(self.body)
        except Exception:
            return None


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[float], Optional[str]]:
    """TCP 三次握手耗时（毫秒）.

    选 TCP 握手而不是 ICMP：境外地址的 ICMP 常被限速或直接丢弃，
    ping 不准而访问正常。TCP SYN/SYN-ACK 更接近真实访问体验，
    而且不需要管理员权限。
    """
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000.0
        return True, elapsed, None
    except socket.timeout:
        return False, None, "timeout"
    except socket.gaierror as exc:
        return False, None, "dns: %s" % exc
    except OSError as exc:
        name = type(exc).__name__
        return False, None, "%s: %s" % (name, exc.strerror or exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def http_get(
    url: str,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    data: Optional[bytes] = None,
) -> HttpResponse:
    """发起一次 HTTP 请求，永远不抛异常."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    request = urllib.request.Request(url, headers=hdrs, method=method, data=data)
    start = time.perf_counter()

    def _elapsed() -> float:
        return (time.perf_counter() - start) * 1000.0

    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310
            body = resp.read(400_000).decode("utf-8", "replace")
            return HttpResponse(
                ok=True,
                status=resp.status,
                body=body,
                elapsed_ms=_elapsed(),
                headers={k.lower(): v for k, v in resp.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(400_000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return HttpResponse(
            ok=True,
            status=exc.code,
            body=body,
            elapsed_ms=_elapsed(),
            headers={k.lower(): v for k, v in (exc.headers or {}).items()},
        )
    except Exception as exc:
        return HttpResponse(
            ok=False,
            status=None,
            body="",
            elapsed_ms=_elapsed(),
            error="%s: %s" % (type(exc).__name__, exc),
        )


def reverse_dns(ip: str, timeout: float = 2.5) -> Optional[str]:
    """反查 PTR，超时返回 None."""
    box = {"value": None}

    def _work() -> None:
        try:
            box["value"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            box["value"] = None

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(timeout)
    return box["value"]


def resolve(host: str, timeout: float = 3.0) -> Tuple[List[str], Optional[str]]:
    """解析主机名，返回 (地址列表, 错误信息)."""
    box = {}

    def _work() -> None:
        try:
            infos = socket.getaddrinfo(host, None)
            seen = []
            for info in infos:
                addr = info[4][0]
                if addr not in seen:
                    seen.append(addr)
            box["value"] = seen
        except Exception as exc:
            box["error"] = "%s: %s" % (type(exc).__name__, exc)

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(timeout)
    if "value" in box:
        return list(box["value"]), None
    if "error" in box:
        return [], str(box["error"])
    return [], "timeout"


def tls_probe(host: str, port: int = 443, timeout: float = 5.0) -> Optional[str]:
    """取对端 TLS 版本，失败返回 None。仅作辅助信息."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return tls.version()
    except Exception:
        return None


def platform_hint() -> str:
    return "%s %s" % (sys.platform, sys.version.split()[0])
