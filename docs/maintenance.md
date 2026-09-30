# 运营机制（P7-T6）

## Chrome stable 新版预设 SLA

- **目标**：Chrome stable 发布后 **2 周内**出新预设（对齐 curl_cffi 的更新节奏）。
- 流程：情报监控 → 抓包/参考 → 构造 detail → 自校验（`gtls_check_profile`
  + `TestPresetsAreValid`）→ L1 回环矩阵 → tls.peet.ws oracle（external tag）
  → evidence 登记 → 入库。
- **"新版已发布"由机器发现，不靠人盯**（审计 A12）：
  `.github/workflows/preset-freshness.yml` 每周一跑 `scripts/preset_freshness.py`，
  比对上游 stable feed 与 `core/profiles/builtin/` 的最高大版本，落后即开
  `preset-staleness` issue（同一时间只维护一条开放 issue，重复落后改为评论）。
  手动跑同一条检查：

  ```bash
  python scripts/preset_freshness.py            # 落后退出码 1；feed 取不到退出码 2
  python scripts/preset_freshness.py --tolerance 2 --json /tmp/fresh.json
  ```

  覆盖面只有 **Chrome / Firefox**（有稳定 JSON feed 且无需 key）；Edge 跟着 Chrome
  的列车看，Safari / Opera / 国产浏览器没有机器可读 stable feed，**仍是人工 SLA**——
  脚本的 `unscored_families` 就是这份"没覆盖"的清单，别把 job 绿读成"全族新鲜"。

## 预设入库流程（一条命令）

1. `core/profiles/builtin/<name>.json` 落 detail（TLS/H2/H3/TCP 各节）。
2. `go test ./tls/ -run TestPresetsAreValid`（编译+自算+warnings 检查）。
3. `go test ./tests/e2e/ -run 'TestPresetsLoopback|TestH2FrameCapture'`
   （L1 字节级）。
4. `GEEKTLS_ORACLE_PRESETS=<新预设名> go test -tags external ./tests/e2e/ -run TestExternalOracle`
   （只打这一条，别为入库一个预设把 364 条全推给第三方 oracle）。
5. `profiles/evidence/README.md` 表格补行（等级/依据/日期）。

## 外部 oracle 与实测闭环（nightly CI）

README 里"✅ 实测 MATCH"这类结论在 `ci.yml` 中**全部是 skip 态**（离线 `go test` 不打外网、
不打动态库、不打真浏览器），所以由 `.github/workflows/oracle-nightly.yml` 专门跑那一档，
失败自动开 `nightly-oracle` issue。四个 job：

| job | 跑什么 | 红意味着 |
|---|---|---|
| `oracle` | `TestExternalOracle` + `TestExternalOracleH2`（`GEEKTLS_ORACLE_ASSERT=1`）、`TestRealECHLive`、`GEEKTLS_LIVE=1` 的会话复用探针 | 指纹侧真漂移（JA3/JA4/Akamai 与 oracle 回读不一致、ECH 握手退化、PSK 复用不再 resumed） |
| `crosslang` | `make build` + `build/echo-server` 二进制 → `TestCrossLangConsistency`（三绑定 JA4 全等）、pytest 全量、node:test 全量 | 绑定层/构件侧回归（这条是**唯一**在 CI 里真打动态库的 job） |
| `h3-browser-e1` | `TestE1RealBrowserH3`（配了仓库变量 `GEEKTLS_E1_H3_BROWSER` 才跑） | H3 与真浏览器不一致 |
| `nginx-l2` | `verify_l2.py`（自建 runner + patched nginx，配 `GEEKTLS_NGINX_L2_URL` 才跑） | 采集端逐字段漂移 |

手动跑同一批（本地排查用）：

```bash
# 注意：core / tests/e2e / bindings/golang 是**各自独立的 module**（没有 go.work，根目录没有
# go.mod），所以必须 cd 进去跑，`go test ./tests/e2e/` 在仓库根会直接报 "main module" 错。

# TLS + H2 oracle：子集用 GEEKTLS_ORACLE_PRESETS（逗号分隔，支持 chrome_* 通配；不设=全量 364 条）
# 默认只打印 MATCH/DIFF（V-3：oracle 自己的解析口径可能变）；CI 里加 ASSERT=1 让 DIFF 判红
(cd tests/e2e && GEEKTLS_ORACLE_PRESETS="chrome_154_windows,edge_153_windows,firefox_156_windows,safari_18_macos,opera_122_windows,chrome_150,chrome_154_macos" \
  GEEKTLS_ORACLE_ASSERT=1 go test -tags external . -run 'TestExternalOracle$|TestExternalOracleH2' -v)
(cd tests/e2e && go test -tags external . -run TestRealECHLive -v)
(cd core/tls && GEEKTLS_LIVE=1 go test -tags external -run TestLiveResumptionProbe -v -timeout 300s)
# 跨语言：echo-server 是**二进制产物**，没有它就 t.Skip（这正是 A3 的成因）
make build && (cd tests/e2e && go build -o ../../build/echo-server$(go env GOEXE) ./cmd/echo-server)
(cd tests/e2e && go test . -run TestCrossLangConsistency -v)
```

- 会话复用探针（`core/tls/resumption_live_test.go`）按 V-3 只打印不断言，nightly 里
  额外用 `resumed=true` 这道 grep 把"第二次握手没复用"变成真失败——否则那条 job
  只证明"握手打得通"。
- `GEEKTLS_ORACLE_PRESETS` 里的模式**一个都没命中 ⇒ 直接失败**（拼错的预设名会让
  "oracle 全绿"变成"什么都没测"）。

## fork rebase 流程

- **vendor fork**：`core/third_party/quic-go-utls`（replace 落地）。
  升级步骤：`third_party/quic-go-utls/GEEKTLS_PATCHES.md` §升级流程——
  覆盖源码 → 重打 6 处 patch（`geektls patch` 锚点可 grep）→ 跑
  `TestQUICInitialSniff` + `TestQUICHelloBisect` 回归。
- **上游 pin**：refraction-networking/utls（go.mod pin v1.8.2）、
  bogdanfinn/fhttp v0.6.9、bogdanfinn/utls v1.7.8-barnius（跟随 fhttp）。
  升级时先跑 `go test ./...` 全模块 + L1 矩阵再谈。

## 情报源清单

| 源 | 用途 | 频率 |
|---|---|---|
| Chrome stable release notes | 新预设触发 | 每版 |
| bogdanfinn/tls-client releases & profiles diff | 预设参数基准 | 每周 |
| curl_cffi releases | 交叉核对 + 更新节奏参照 | 每周 |
| refraction-networking/utls releases | TLS 栈升级 | 每周 |
| FoxIO ja4 spec / ja4plus-go | JA4 规则与向量更新 | 每月 |
| tls.peet.ws 行为变化 | oracle 基线漂移 | 周检时顺带 |

## 工作区与推送副本的一致性（幽灵文件）

云编译红过三次，其中两次根因都在这儿，**与代码无关**：

1. 2026-09-29 `bindings/python/pyproject.toml`：本地已删掉与 PEP 639 冲突的
   `License ::` classifier，远端还是旧内容 ⇒ 5 个平台一起红（报错发生在
   `get_requires_for_build_wheel`，与平台/Go/容器无关，别往那上面找）。
2. 2026-09-30 `core/tcp/sockopt_unix.go`：本地已把它改名成 `sockopt_darwin.go`
   并收窄约束，远端**两份都在** ⇒ mac 上 `applySockopts` 等三重声明冲突，
   **只有 darwin runner 红**，linux/windows 全绿。

共同点：**远端不是本地工作区的镜像**——改名/删除不会传播，构建产物的历史副本也留着。
凡"本地绿、云上红，且报错像是文件重复或内容过期"，先做这一步对照：

```bash
# 只取远端文件清单（不下载 blob，秒级）
rm -rf /tmp/remrepo && git clone --depth=1 --filter=blob:none --no-checkout -q \
  https://github.com/geekbyter/geektls /tmp/remrepo
git -C /tmp/remrepo ls-tree -r --name-only HEAD | sort > /tmp/remote_files.txt
find . -type f -not -path './.git/*' -not -path './build/*' | sed 's|^\./||' | sort > /tmp/local_files.txt
comm -23 /tmp/remote_files.txt /tmp/local_files.txt   # 远端有、本地没有 = 幽灵文件
comm -13 /tmp/remote_files.txt /tmp/local_files.txt   # 本地有、远端没有 = 还没推上去
```

处理原则：

- **幽灵文件必须在远端删除**（`git rm <path>` 后推，或网页上删）。本地补一个同名文件
  只有在"推送会覆盖同名路径"时才管用，别赌这条。
- 构建产物（`bindings/python/build/`、`dist-*/`、`*.egg-info/`）本就不该入库，
  `.gitignore` 已覆盖；已入库的用 `git rm -r --cached <path>` 撤出跟踪。
- CI 能自动挡的是"平台文件互斥/漏覆盖"（`ci.yml` 的 **cross-OS compile gate**），
  挡不住推送副本本身不一致 —— 那部分只有上面这条对照能做。

## 版本号升级规则

见 docs/versioning.md：core/bindings 三处同步；ABI 破坏性变更才升 abi 号；
发布前三语言冒烟 + pytest + node:test 全绿是门禁。
