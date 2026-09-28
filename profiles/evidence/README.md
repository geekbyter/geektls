# presets evidence（预设证据登记）

每个入库预设必须附证据记录，满足 03 文档 §3"预设入库即测试"原则。
记录要素：**构造依据 / 验证状态 / 验证日期**。

## 证据等级

| 等级 | 含义 |
|---|---|
| E1 实测 | 有真浏览器 pcap/采集端逐字段 diff |
| E2 外部 oracle | tls.peet.ws 回读 JA3/JA4/Akamai 全 MATCH |
| E3 权威转写 | 转写自 uTLS parrot（其本身经社区核验）/tls-client 公开参数 |
| E4 知识构造 | 公开资料推断，待 E1/E2 终审 |

## 现有预设

| 预设 | TLS | H2 | H3 | 证据 |
|---|---|---|---|---|
| chrome_131 | E2+E3（uTLS HelloChrome_131 转写；tls.peet.ws JA4 `t13d1516h2_8daaf6152771_02713d6af862` MATCH，2026-09-21） | E2（Akamai `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` MATCH） | E4（Chrome QUIC 公开参数） | 待 L2 nginx 终审 |
| chrome_133 | E2+E3（HelloChrome_133 转写；oracle JA3/JA4 MATCH，2026-09-21） | E2（MATCH） | E4 | 同上 |
| chrome_150 | E2（oracle MATCH，2026-09-21；TLS detail 与 133 同形——150 未出新 parrot，按公开记录构造） | E2（MATCH） | E4 | 同上 |
| firefox_120 | E2+E3（HelloFirefox_120 转写；oracle MATCH，2026-09-21） | E2（MATCH） | —（未填，TODO） | 同上 |
| firefox_135 | E2（oracle MATCH；E4 构造：120 基线 + MLKEM key_share 首位） | E2（MATCH） | —（TODO） | 同上 |
| firefox_156_windows | **E1r**（真 Firefox 156 / Windows 字段级实测：cipher 顺序 / 扩展集合 / groups / sig_algs / DC / RSL / 证书压缩全等，见 docs/07 §6.3） | E1r（同实测 SETTINGS `[1:65536,2:0,4:131072,5:16384]` / WU 12517377 / 伪头 `m,p,a,s`） | —（待真实 Firefox H3 抓包） | 2026-09-24 新增；回归 `firefox_groundtruth_test.go`；**无原始字节**故记 E1r（区别字节级 E1） |
| safari_16 | E2+E3（HelloSafari_16.0 转写；oracle MATCH，2026-09-21） | E2（MATCH） | —（TODO） | 同上 |
| safari_18 | E2（oracle MATCH；E4 构造：16 基线 + MLKEM） | E2（MATCH） | —（TODO） | 同上 |

## 抓包生成预设（2026-09-24，T2-2）

以下预设由 `tests/e2e/cmd/gen-profiles` 从真实浏览器抓包直接生成
（标本本地冻结于 `tests/e2e/specimens/data.go`），不再依赖手写转录：

| 预设 | TLS | H2 | H3 | 证据 |
|---|---|---|---|---|
| chrome_137/141/142/143/152_macos | E1（真实抓包） | E1（同抓包 SETTINGS/WINDOW_UPDATE） | E4（Chromium 家族继承 chrome_150；逐版本待 E1） | 语料回归逐字段对拍通过 |
| edge_141_macos | E1 | E1 | E4（家族继承） | 同上 |
| firefox_140/144_macos | E1 | E1 | —（待真实 Firefox H3 抓包） | 同上（PSK 扩展按 fresh 语义省略） |
| safari_18/26_macos | E1 | E1 | —（待真实 Safari H3 抓包） | 同上 |

生成语义与已知边界：

- `tls.detail` 逐字段来自抓包；GREASE 字面值归一为占位符，扩展 `type` 另标
  `grease_random`（两者都保留浏览器「每连接重随机化」行为）；`sig_algs` 的 GREASE 位
  由 compile 在编译期取值——uTLS 不做该处的握手期替换（见 07 文档 G12）。
- `extension_permutation`：Chrome/Edge 置 true（逐连接洗牌），Firefox/Safari 不洗牌。
- `sni` 统一为 `auto`（抓包现场的 host 不固化进预设）。
- `http2.pseudo_header_order` 标本内不可得，取浏览器族固定顺序（Chrome/Edge `m,a,s,p`、
  Firefox `m,p,a,s`、Safari `m,s,a,p`）——**该项仍为知识构造（E4）**，待 nginx 采集端实测校正。
- 无 `tcp` 节：TCP 层需 pcap，标本不含。

## 真浏览器 E1 基准（2026-09-24，`tests/e2e/cmd/e1-browser`）

链路：本地无头真实浏览器 → 本地 fp 采集端（独立解析器）→ 与内置预设逐字段对照。
记录落盘含**原始 ClientHello hex**，可直接作为后续标本/语料来源。

| 记录 | 浏览器 | 对照预设 | 结果 |
|---|---|---|---|
| `browsers/chrome_windows.json` | Chrome 149.0.7827.54 (Windows) | `chrome_150` | ✅ **逐字段完全一致**（ciphers / 扩展集合 / curves / points / versions / sig_algs / ALPN + H2 SETTINGS/WINDOW_UPDATE）；JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| `browsers/edge_windows.json` | Edge 153.0.4234.48 (Windows) | `edge_141_macos` | ⚠️ 1 处差异：真 Edge 的 `sig_algs` 多 `0x0904/0x0905/0x0906`（rsa_pss_pss_*，Chromium ≥150 新增；`chrome_152_macos` 预设已含这三项） |

> 这是首批**非同源自证**的证据——此前所有 MATCH 都是"我们发出的 == 我们想发的"。
> 相关观察：同一浏览器两次抓包的扩展顺序不同而 JA4 相同（逐连接洗牌，印证
> `extension_permutation` 建模）；本机 Chrome 149 / Edge 153 的 `sig_algs` **不含**
> GREASE，而 `chrome_152_macos` 真标本含 `0xEAEA` —— 疑为版本差异，待 152 真机复核。

由 E1 记录直接产出预设（T2-2 链路，一条命令可复现；CI 有守门保证"入库 == 生成器产物"）：

```bash
cd tests/e2e
go run ./cmd/gen-profiles -out ../../core/profiles/builtin \
  -record ../../profiles/evidence/browsers/chrome_windows.json,../../profiles/evidence/browsers/edge_windows.json
```

产物：`chrome_149_windows`、`edge_153_windows`（E1）。与抓包标本唯一差别是
**identity 直接用抓包里的真实请求头**（真实 UA-CH 比合成值可靠；实测已发现
UA-CH 的 GREASE 品牌名称/版本/位置随浏览器版本变化）。H3 记录
（`chrome_windows_h3.json`）当前用于 transport params 实测，尚不参与预设生成。

## 待补证据（与 P1-T8/P6-T3 同环境）

- 真浏览器 H3/QUIC 采集（E1）：**Chrome 已完成**（`browsers/chrome_windows_h3.json`；
  链路见 `tests/e2e/e1_h3_test.go`：`--origin-to-force-quic-on` 强制走 QUIC + RFC 9001
  Initial 嗅探）。**Firefox / Safari 仍缺**——它们的 H3 transport params 与 Chromium
  不同、不能家族继承，需在对应浏览器上跑同一条链路
  （`GEEKTLS_E1_H3_BROWSER=<firefox 路径>` 即可）。
- QUIC transport params 与 H3 settings 的 E2 验证（需支持 H3 的 oracle 或
  nginx 采集端）。
- 每预设的 tcp 节为宿主 OS 口径（docs/tcp-platform-matrix.md），待 pcap 分级。

> 2026-09-24：状态快照与阻塞项的机器可读版本见 [../docs/capability-matrix.yml](../../docs/capability-matrix.yml)；阶段计划见 [../docs/plans/2026-09-24-geektls-hardening-and-h3-plan.md](../../docs/plans/2026-09-24-geektls-hardening-and-h3-plan.md)；已验证面冻结契约见 [../docs/CONTRACT-FREEZE.md](../../docs/CONTRACT-FREEZE.md)。
