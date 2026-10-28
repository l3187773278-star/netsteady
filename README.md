# netsteady

跨境链路稳定性监测 + 出口 IP 纯净度体检。零依赖，纯标准库，Python 3.9+。

[![CI](https://github.com/l3187773278-star/netsteady/actions/workflows/ci.yml/badge.svg)](https://github.com/l3187773278-star/netsteady/actions/workflows/ci.yml) ![python](https://img.shields.io/badge/python-3.9%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

**完整讲解**：https://l3187773278-star.github.io/netsteady/

## 安装

```bash
git clone https://github.com/l3187773278-star/netsteady.git
cd netsteady
python -m netsteady --help
```

或装成命令：

```bash
pip install -e .
netsteady --help
```

## 用法

### 出口 IP 体检

```bash
python -m netsteady ip
```

| 参数 | 说明 |
|---|---|
| `--services LIST` | 要探测的服务，逗号分隔或 `all`，默认 `all`（14 个） |
| `--no-services` | 跳过服务探测，只看出口 IP |
| `--dnsbl` | 额外查公共黑名单 |
| `--json` | 输出 JSON |
| `--timeout SEC` | 单次请求超时，默认 10 |

### 持续监测跨境链路

```bash
python -m netsteady watch -d 10m --html report.html
```

| 参数 | 说明 |
|---|---|
| `-d, --duration` | 总时长，如 `90s` `10m` `2h`；省略则直到 Ctrl+C |
| `-i, --interval` | 探测间隔，默认 `2s` |
| `-t, --timeout` | 单次探测超时，默认 `3s` |
| `--target HOST[:PORT]` | 追加自定义目标，可重复 |
| `--targets FILE` | 从 JSON 加载目标清单，示例见 `examples/targets.json` |
| `--no-domestic` | 不探测境内对照组 |
| `--jsonl PATH` | 原始采样，追加写入，可中断续跑 |
| `--csv PATH` | 汇总指标 |
| `--text PATH` | 文本报告 |
| `--html PATH` | 单文件 HTML 报告 |
| `--no-live` | 关闭实时刷新表格 |
| `--quiet` | 只输出最终报告 |

### 真实地址暴露面

```bash
python -m netsteady leak
```

| 参数 | 说明 |
|---|---|
| `--json` | 输出 JSON |
| `--timeout SEC` | 单次探测超时，默认 8 |

### 其他

```bash
python -m netsteady targets    # 列出内置目标
python -m netsteady --version
```

## 开发

```bash
python -m unittest discover -s tests -t . -v
```

## License

MIT
