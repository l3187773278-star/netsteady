"""命令行入口."""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional, Sequence

from . import __version__, ipcheck, targets as targets_mod, watch
from .model import Target
from .report import pad

_UNITS = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}


def parse_duration(text: str) -> float:
    raw = str(text).strip().lower()
    if not raw:
        raise argparse.ArgumentTypeError("空的时长")
    unit = 1.0
    if raw[-1] in _UNITS:
        unit = _UNITS[raw[-1]]
        raw = raw[:-1]
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("无法解析时长：%s" % text)
    if value < 0:
        raise argparse.ArgumentTypeError("时长不能为负")
    return value * unit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsteady",
        description="跨境网络稳定性监测 + 出口 IP 纯净度体检（零依赖，纯标准库）",
        epilog="示例：netsteady watch -d 10m --html report.html / netsteady ip",
    )
    parser.add_argument("-V", "--version", action="version", version="netsteady " + __version__)
    subparsers = parser.add_subparsers(dest="command")

    watch_parser = subparsers.add_parser("watch", help="持续监测跨境链路稳定性")
    watch_parser.add_argument("-d", "--duration", type=parse_duration, default=None, help="总时长，如 90s / 10m / 2h；省略则直到 Ctrl+C")
    watch_parser.add_argument("-i", "--interval", type=parse_duration, default=2.0, help="探测间隔，默认 2s")
    watch_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="单次探测超时，默认 3s")
    watch_parser.add_argument("--target", action="append", default=[], metavar="HOST[:PORT]", help="追加自定义目标，可重复")
    watch_parser.add_argument("--targets", default=None, metavar="FILE", help="从 JSON 文件加载目标清单")
    watch_parser.add_argument("--no-domestic", action="store_true", help="不探测境内对照组")
    watch_parser.add_argument("--jsonl", default=None, metavar="PATH", help="追加写入原始采样（可中断续跑）")
    watch_parser.add_argument("--html", default=None, metavar="PATH", help="输出单文件 HTML 报告")
    watch_parser.add_argument("--csv", default=None, metavar="PATH", help="输出汇总 CSV")
    watch_parser.add_argument("--text", default=None, metavar="PATH", help="同时把文本报告写入文件")
    watch_parser.add_argument("--no-live", action="store_true", help="关闭实时刷新表格")
    watch_parser.add_argument("--quiet", action="store_true", help="完全不输出过程，只给最终报告")

    ip_parser = subparsers.add_parser("ip", help="体检当前出口 IP（面向 Claude / ChatGPT）")
    ip_parser.add_argument("--services", default="claude,openai", metavar="LIST", help="要探测的服务，逗号分隔，默认 claude,openai")
    ip_parser.add_argument("--dnsbl", action="store_true", help="额外查询公共 DNS 黑名单（较慢且常被拒绝）")
    ip_parser.add_argument("--json", action="store_true", help="输出 JSON，便于脚本消费")
    ip_parser.add_argument("--timeout", type=float, default=10.0, help="单次 HTTP 超时，默认 10s")

    subparsers.add_parser("targets", help="列出内置目标")
    return parser


def _setup_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def cmd_watch(args: argparse.Namespace) -> int:
    try:
        base_targets: List[Target] = targets_mod.load_targets(args.targets)
    except Exception as exc:
        print("加载目标失败：%s" % exc, file=sys.stderr)
        return 2

    for spec in args.target:
        try:
            base_targets.append(targets_mod.parse_endpoint(spec))
        except Exception as exc:
            print("目标格式错误 %r：%s" % (spec, exc), file=sys.stderr)
            return 2

    if args.no_domestic:
        base_targets = [t for t in base_targets if t.group != "domestic"]
    if not base_targets:
        print("没有可用目标。", file=sys.stderr)
        return 2

    payload = watch.run(
        base_targets,
        interval=max(0.2, args.interval),
        duration=args.duration,
        timeout=args.timeout,
        jsonl_path=args.jsonl,
        live=not args.no_live,
        quiet=args.quiet,
    )
    watch.finalize(
        base_targets,
        payload,
        html_path=args.html,
        csv_path=args.csv,
        text_path=args.text,
    )
    return 0


def cmd_ip(args: argparse.Namespace) -> int:
    services = [s.strip() for s in (args.services or "").split(",") if s.strip()]
    unknown = [s for s in services if s not in ipcheck.SERVICES]
    if unknown:
        print("未知服务：%s（可选 %s）" % ("、".join(unknown), "、".join(ipcheck.SERVICES)), file=sys.stderr)
        return 2

    report = ipcheck.run(services=services, dnsbl=args.dnsbl, timeout=args.timeout)
    if args.json:
        print(ipcheck.render_json(report))
    else:
        print(ipcheck.render_text(report))
    return 0


def cmd_targets(_: argparse.Namespace) -> int:
    rows = list(targets_mod.OVERSEAS_PRESETS) + list(targets_mod.DOMESTIC_PRESETS)
    widths = [8, 24, 26]
    print("".join(pad(text, width) for text, width in zip(["组别", "地址", "备注"], widths)))
    print("-" * 78)
    for target in rows:
        cells = ["境内" if target.group == "domestic" else "境外", target.endpoint, target.note]
        print("".join(pad(text, width) for text, width in zip(cells, widths)).rstrip())
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    _setup_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    handlers = {"watch": cmd_watch, "ip": cmd_ip, "targets": cmd_targets}
    return handlers[args.command](args)
