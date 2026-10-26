# netsteady

跨境链路稳定性监测 + 出口 IP 纯净度体检。**零依赖，纯标准库，跨平台。**

[![CI](https://github.com/l3187773278-star/netsteady/actions/workflows/ci.yml/badge.svg)](https://github.com/l3187773278-star/netsteady/actions/workflows/ci.yml) ![python](https://img.shields.io/badge/python-3.9%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

`netsteady` 回答两个具体问题：

1. **我的跨境链路稳不稳？** 境内 → 境外这一段的丢包、尾延迟、断流，以及什么时候开始劣化。
2. **我的出口 IP 干不干净？** 拿这个 IP 去访问 Claude / ChatGPT，属于哪一类风险特征。
3. **具体哪些 AI 服务能过？** 14 个限制中国 IP 的服务逐个探测：域名解析到哪个 IP、那个 IP 归属哪里、握手多少毫秒、是被硬挡还是被 WAF 质询。
4. **它们能不能看穿我在国内？** 单独查绕过代理的暴露面：IPv6、UDP/STUN、DNS 出口、系统时区与语言。

> 它不测带宽，也不做吞吐压测。跨境体验的瓶颈通常不是带宽，而是丢包和尾延迟。

---

## 为什么不是 ping

如果只做 ping，这个工具没有存在意义。三个刻意为之的设计：

**1. 用 TCP 握手代替 ICMP。** 境外目标的 ICMP 常被限速或直接丢弃，`ping 8.8.8.8` 丢 20% 的时候网页往往还能正常打开。TCP SYN/SYN-ACK 的耗时更接近真实访问，而且不需要管理员权限。

**2. 双轨对照，而不是单目标。** 只看“境外某 IP 丢包 30%”判断不了是谁的问题。工具默认同时探测一组境内目标作为基线：境内也烂 = 你本地或宽带的问题；境内正常而多个境外目标同时劣化 = 国际出口的问题；只有一个境外目标烂 = 目标自身的问题。结论直接写在报告里。

**3. 按小时聚合，而不是一个平均值。** 跨境链路是规律性劣化的：晚高峰 20:00–24:00 丢包抬升，白天恢复。单次测量几乎看不出这个模式，按整点分桶后一眼就能看出来。

---

## 安装

```bash
git clone https://github.com/l3187773278-star/netsteady.git
cd netsteady
python -m netsteady --help
```

也可以直接安装成命令（需要 Python 3.9+）：

```bash
pip install -e .
netsteady --help
```

---

## 用法一：出口 IP 体检

```bash
python -m netsteady ip
```

实测输出（2026-10-26，本机走美国 LA 出口）：

```text
==================================================================
 netsteady · 出口 IP 纯净度体检
==================================================================
 出口 IP    203.0.113.219  （美国 California Los Angeles）
 归属       AS64496 EXAMPLE HOSTING LTD
 网络类型   公开代理
 DNS 出口   Japan - Google LLC  203.0.113.53

 综合评分   59 / 100   ██████████████░░░░░░░░░░   可信度：中

 检查明细
   ✓ 出口 IP 一致性  多家出口服务返回同一 IP  (10/10)
   ✓ 地理一致性      3 个来源一致指向 United States  (25/25)
   ✗ 网络类型        公开代理特征  (4/25)
   ! DNS 出口        解析器出口 Japan - Google LLC 与 IP 归属 United States 不一致，
                     DNS 可能泄漏真实位置  (6/20)
   ! 链路可信度      ASN 完整；运营商信息可查  (11/15)
   – 公共黑名单      未启用（加 --dnsbl 开启，公共 DNS 常被 DNSBL 拒绝）

 目标服务（域名解析 → IP 属地 → 连通性 → 区域限制）
   服务                 域名                               解析 IP          IP 属地               握手  结果
   -----------------------------------------------------------------------------------------------------
   ! Claude             claude.ai                          160.79.104.10    美国 · San Francisco  4ms   WAF 质询
   ✓ Claude API         api.anthropic.com                  160.79.104.10    美国 · San Francisco  2ms   可达
   ! ChatGPT            chatgpt.com                        172.64.155.209   加拿大 · Toronto      1ms   WAF 质询
   ✓ OpenAI Codex       chatgpt.com                        172.64.155.209   加拿大 · Toronto      1ms   可达
   ✓ OpenAI API         api.openai.com                     162.159.140.245  加拿大 · Toronto      3ms   可达
   ✓ Google Gemini      gemini.google.com                  142.251.156.2    美国 · New Haven      3ms   可达
   ! Gemini API         generativelanguage.googleapis.com  172.217.113.4    美国 · Mountain View  3ms   WAF 质询
   ✓ Microsoft Copilot  copilot.microsoft.com              104.18.23.222    加拿大 · Toronto      1ms   可达
   ? GitHub Copilot     api.githubcopilot.com              140.82.113.22    美国 · San Francisco  1ms   未知
   ! Perplexity         perplexity.ai                      104.18.27.48     加拿大 · Toronto      1ms   WAF 质询
   ✓ xAI Grok           grok.com                           104.18.29.234    加拿大 · Toronto      1ms   可达
   ! Mistral            chat.mistral.ai                    141.101.90.105   德国 · Munich         18ms  WAF 质询
   ! Midjourney         midjourney.com                     172.64.154.39    加拿大 · Toronto      1ms   WAF 质询
   ✓ Cursor             cursor.com                         76.76.21.21      美国 · Walnut         20ms  可达

   注意：本机 DNS 返回的是 fake-ip（198.18.0.0/15），上表的解析 IP 已改用 DoH 取得。

 结论：7/14 个服务可达；遭遇 WAF 质询 6 个（Claude、ChatGPT、Gemini API）。
==================================================================
```

### 目标服务：解析 → 属地 → 连通 → 判定

对每个会限制中国 IP 的 AI 服务，走完四步：

1. **解析**：先问本机 DNS，如果拿到 `198.18.0.0/15`（TUN 代理的 fake-ip）就自动改走 DoH（依次尝试 dns.google → doh.pub → 阿里 → Cloudflare），拿到真实解析 IP
2. **属地**：一次 `ip-api` 批量查询，把这批 IP 的国家/城市一起取回来
3. **连通**：TCP 握手连两次取最小值（TUN 会缓存会话，第一次常被本地协议栈秒回，单次测量不准）
4. **判定**：看 HTTP 响应，区分四种结局

| 结果 | 含义 | 判据 |
|---|---|---|
| ✓ 可达 | 服务接收了你的请求 | 2xx，或 401/404/405（无凭据的正常拒绝） |
| ✗ 区域拒绝 | 明确因地区被挡 | 响应体命中 `unsupported_country`、`not available in your region` 等 |
| ! WAF 质询 | IP 被判定为可疑，弹出人机验证 | 403 + `cf-mitigated: challenge` / `Just a moment...` |
| ✗ 连不上 | DNS 或 TCP 层面就断了 | 解析失败 / 握手失败 |

WAF 质询和区域拒绝要分开看：前者说明 IP 不干净但服务本身对你开放，后者是硬挡。

内置 14 个服务：Claude（网页 + API）、ChatGPT、OpenAI Codex、OpenAI API、Google Gemini（网页 + API）、Microsoft Copilot、GitHub Copilot、Perplexity、xAI Grok、Mistral、Midjourney、Cursor。

```bash
python -m netsteady ip                          # 全部 14 个
python -m netsteady ip --services claude,chatgpt,codex   # 只看这几个
python -m netsteady ip --no-services            # 跳过，只看出口 IP
python -m netsteady ip --json                   # 机器可读
```

### 评分怎么来的

六个维度，全部来自公开数据，权重和扣分逻辑写在代码里，不做黑盒：

| 维度 | 权重 | 数据来源 |
|---|---|---|
| 出口 IP 一致性 | 10 | Cloudflare trace / ip.sb / AWS checkip 三家交叉 |
| 地理一致性 | 25 | ip-api / ip.sb / ipapi.co 三家国家字段是否一致 |
| 网络类型 | 25 | `hosting` `proxy` `mobile` 标记 + ASN/组织名关键词 + 反查 |
| DNS 出口 | 20 | EDNS 回显的解析器出口是否与 IP 同区 |
| 链路可信度 | 15 | ASN 完整性、反查、能否与目标站点建连 |
| 公共黑名单 | 15 | Spamhaus / SpamCop / Barracuda（`--dnsbl` 开启）|

权重和分数是启发式的，**不等同于服务商内部风控结论**。Claude 和 ChatGPT 的真实风控还包含账号历史、浏览器指纹、行为模式，这些从外部无法复现，任何号称能算出来的工具都是编的。

---

## 用法二：持续监测跨境链路

```bash
# 跑 10 分钟，实时刷新，结束时输出 HTML 报告
python -m netsteady watch -d 10m --html report.html

# 跑一整晚，原始数据落盘，中途 Ctrl+C 也不会丢
python -m netsteady watch --jsonl night.jsonl --csv night.csv

# 指定自己的目标（比如你的境外 VPS），端口可省略（默认 443）
python -m netsteady watch --target 203.0.113.10:443 --target 198.51.100.7
```

实测输出（20 秒，本机走 TUN 代理）：

```text
【目标概览】
目标                    组别  样本  丢包%  最小  中位  P95  P99  抖动  最长断流
-----------------------------------------------------------------------------
cf-1.1.1.1              境外      10    0.0     1     5   18   19     9        0s
goog-dns-8.8.8.8        境外      10    0.0     1     3   22   23    10        0s
quad9-9.9.9.9           境外      10    0.0     1     2   25   30    12        0s
cn-114                  境内      10    0.0     1     1    7    7     1        0s

【提示】
 以下境外目标的中位 RTT 低得不合常理（< 8ms），通常意味着流量被本地代理
 或 TUN 模式接管，或该目标走的是就近 anycast 节点：此时你测到的是本地
 协议栈的响应，而不是真实的跨境物理链路。
   cf-1.1.1.1、goog-dns-8.8.8.8、quad9-9.9.9.9

【分时段聚合】
目标                    18:00    19:00    20:00    21:00
---------------------------------------------------------
cf-1.1.1.1              0%/5     0%/6     3%/41   12%/88
cn-114                  0%/1     0%/1     0%/1     0%/2

【结论】
 [BAD ] 跨境链路劣化（境内正常，境外多目标同时异常）
```
（最后一张表是示意，用来说明 20:00 之后的分时段劣化长什么样；前两段是真实输出。）

### 输出文件

| 参数 | 内容 |
|---|---|
| `--jsonl PATH` | 每次探测一行 JSON，追加写入，可中断续跑 |
| `--csv PATH` | 每个目标的汇总指标 |
| `--text PATH` | 终端看到的文本报告 |
| `--html PATH` | 单文件 HTML：内联 CSS + 内联 SVG，离线可看，无外部请求 |

---

## 用法三：真实地址暴露面

`ip` 回答"这个 IP 像不像代理"，`leak` 回答一个更根本的问题：**就算 IP 伪装好了，服务商有没有别的路子知道我实际在哪。**

```bash
python -m netsteady leak
```

实测输出：

```text
 出口 IPv4  203.0.113.219  （美国）
 本机指纹   UTC+8  时区 中国标准时间  语言 Chinese (Simplified)_China

 检查项             风险  判定
 ! DNS 解析出口     中    可疑
                                IP 归属 United States，但 DNS 解析出口在 Japan - Google LLC。
 ✗ 系统时区 / 语言  中    泄漏
                                系统时区 UTC+8、语言 Chinese (Simplified)_China，IP 却在 美国。
                                浏览器会把这两项主动上报给网站，比 IP 本身更能说明你实际在哪。
 ✓ IPv6 出口        低    正常
                                IPv6 出口 2001:db8:4a7f:... 与 IPv4 同属美国（Example Hosting Ltd），
                                是代理自己的双栈地址，没有泄露你的位置。
 ✓ UDP / STUN       低    正常
                                STUN 回显 203.0.113.173，与 IPv4 出口 .219 不同，但同属美国。
 ✓ CDN 接入点       提示  正常
                                请求落在 Cloudflare LAX 节点。
```

### 五条通道，各有各的判断方式

| 通道 | 怎么测 | 什么才算真泄漏 |
|---|---|---|
| IPv6 出口 | 请求一个只回 IPv6 的回显服务，再查这个 v6 的归属 | **归属中国**才是泄漏；归属和 v4 同国，说明只是代理的双栈地址 |
| UDP / STUN | 自己组 STUN Binding Request 发到三台公共 STUN 服务器，解析回包里的 XOR-MAPPED-ADDRESS | **归属中国**才是泄漏；地址不同但同国，多半是代理的 NAT 地址池 |
| DNS 出口 | 用 EDNS 回显看解析器从哪个国家出去 | 和 IP 属地不一致就算可疑，因为 ECS 会把位置转告给 CDN |
| 系统时区 / 语言 | 读本机 UTC 偏移、时区名、locale | 浏览器用 `Intl` 和 `Accept-Language` 主动上报，矛盾时是硬指纹 |
| CDN 接入点 | Cloudflare trace 里的 `colo` | 只作参考，说明流量实际落在哪个边缘节点 |

第二列有个容易踩的坑：**地址不一样 ≠ 泄漏**。第一版工具直接把"STUN 回的地址 ≠ HTTP 出口地址"判成高危，结果全是误报——同一个代理的 NAT 池本来就会给出不同地址。改成比对归属地之后，两条高危降成了正常。

### 两条轴，别混为一谈

报告最后会写一句话，值得单独拎出来：

> 看不到你的真实地址，不等于这个 IP 就是纯净的。

这两件事是完全独立的：

| | 问题 | 判据 | 结果 |
|---|---|---|---|
| **定位风险** | 它能知道你在地球上哪个位置吗 | IPv6 / STUN / DNS / 时区语言 | `leak` 命令 |
| **身份风险** | 它能看出来你在用代理吗 | 机房 ASN、hosting 标记、WAF 质询 | `ip` 命令 |

一个家宽 IP 可能定位精准（没有任何泄漏通道），但它上过太多共享代理，照样被风控；反过来，一个机房 IP 可能完全不泄漏位置，却因为 ASN 写着 DigitalOcean 而被一眼看穿。**这两项都过关，才叫"干净"。**

---

## 指标说明

| 指标 | 含义 | 为什么重要 |
|---|---|---|
| 丢包% | 探测失败占总探测数 | 跨境链路上丢包比高延迟更致命，TCP 会因此反复重传 |
| 中位（P50） | 半数请求快于该值 | 代表“通常的体感” |
| P95 / P99 | 尾延迟 | 决定你会不会突然卡一下，比平均值有用得多 |
| 抖动 | 相邻 RTT 差的平均绝对值 | 抖动大意味着路由或出口拥塞，语音/游戏会明显有感 |
| 最长断流 | 连续失败区间的最长时长 | 一次性断 30 秒比丢 5% 更难受 |
| 分时段 | 按本地整点聚合的丢包/中位 | 识别晚高峰规律 |

---

## 判定逻辑

```text
境内对照组劣化                    → 本地网络异常（先查你自己的宽带）
境内正常 + ≥2 个境外目标劣化      → 跨境链路劣化（国际出口拥塞）
境内正常 + 只有 1 个境外目标劣化  → 单目标异常（目标自身限流/路由不友好）
全部正常                          → 跨境链路稳定
```

劣化的定义：丢包 ≥ 5%，或 P95/P99 同时超过中位的 2 倍且多出 40ms 以上。加绝对下限是为了避免在 10ms 的链路上把 21ms 误判成劣化。

---

## 已知限制

- **anycast 目标测不到真实跨境 RTT。** 1.1.1.1、8.8.8.8 这类任播地址会就近接入，你可能只是在和本省/本国的节点握手。要测真实跨境路径，请用 `--target` 指定一个固定位置的 IP（比如你自己的境外 VPS）。工具会在出现 < 8ms 的异常低延迟时主动提示。
- **假 IP 会让测量失真。** 如果你的代理用了 TUN + fake-ip 模式（特征：域名解析到 `198.18.0.0/15`），所有 TCP 握手都由本地代理应答。工具会自动识别并改用 DoH 取真实解析 IP，但握手耗时仍然是"到你本地代理"的，不是物理跨境 RTT。
- **DoH 不是万能的。** 四个 DoH 端点都可能被同一层拦截；全部失败时表格里会显示本机解析结果（fake-ip），并在表下标注。
- **不测 UDP / QUIC。** 纯 TCP 视角，QUIC 的表现可能更好或更差。
- **单机视角。** 没有分布式探针，只能说明“从我这台机器看”。
- **DNSBL 多数不可用。** 公共 DNS 会被 Spamhaus 等拒绝查询，该维度常直接跳过并自动归一化权重。
- **纯净度评分是启发式。** 它衡量的是“公开资料显示的特征”，不是服务商的裁决。

---

## 开发

```bash
python -m unittest discover -s tests -t . -v   # 54 个单元测试，全部离线
python -m netsteady ip                         # 会发起真实网络请求
```

目录：

```text
netsteady/
  net.py           TCP 握手、HTTP、DNS 原语
  stats.py         分位数、抖动、断流、分时段、判定（纯函数）
  watch.py         并发监测循环 + 实时表格
  ipcheck.py       出口 IP 体检与评分
  report.py        文本表格 / CSV（含中日韩字符宽度对齐）
  html_report.py   单文件 HTML（内联 SVG 时线图 + 热力表）
  cli.py           命令行
tests/             离线单元测试
```

---

## English

`netsteady` is a zero-dependency CLI for **cross-border link stability** and **egress IP hygiene**, written for the China → overseas path.

Two subcommands: `watch` (TCP-handshake probe loop with a domestic control group, hourly bucketing, JSONL/CSV/HTML reports) and `ip` (egress IP reputation snapshot aimed at Claude / ChatGPT, with a transparent heuristic score).

```bash
python -m netsteady ip     # egress IP purity + 14 AI services
python -m netsteady leak   # can they still tell where you really are?
python -m netsteady watch -d 10m --html report.html
```

No third-party packages. Python 3.9+. MIT licensed.

---

## License

MIT
