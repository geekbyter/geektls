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
| safari_16 | E2+E3（HelloSafari_16.0 转写；oracle MATCH，2026-09-21） | E2（MATCH） | —（TODO） | 同上 |
| safari_18 | E2（oracle MATCH；E4 构造：16 基线 + MLKEM） | E2（MATCH） | —（TODO） | 同上 |

## 待补证据（与 P1-T8/P6-T3 同环境）

- 真浏览器 pcap（E1）：chrome_150 / firefox_135 / safari_18 三个 E4 项优先。
- QUIC transport params 与 H3 settings 的 E2 验证（需支持 H3 的 oracle 或
  nginx 采集端）。
- 每预设的 tcp 节为宿主 OS 口径（docs/tcp-platform-matrix.md），待 pcap 分级。
