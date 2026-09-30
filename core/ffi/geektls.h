/*
 * geektls.h — geektls core C ABI v1（手写维护的权威契约，实现见 core/ffi/exports.go）。
 *
 * 规则摘要（完整契约见 docs/02-ffi-abi.md）：
 *   - JSON 进、JSON 出；handle 为 uint64_t，0 表示无效/失败。
 *   - 返回 char* 的函数把内存所有权移交调用方，必须用 gtls_free_string() 释放；
 *     返回 NULL 表示失败，错误详情取 gtls_last_error()。
 *   - 返回 int 的函数：0 = 成功，-1 = 失败（细节同样走 gtls_last_error）。
 *   - 错误详情有两个入口：gtls_last_error 是当前线程的，gtls_error_of(handle)
 *     是"这个对象最近一次失败"的——后者给把阻塞调用放到 worker 线程的绑定用。
 *   - 所有函数线程安全；同一 session handle 可并发发请求（二期阶段 5 起，
 *     引擎内连接池加锁）；response/upload handle 仍不得并发使用；panic 不越过 ABI。
 */
#ifndef GEEDTLS_H
#define GEEDTLS_H

#include <stdint.h>

#ifdef _WIN32
#  ifdef GEEDTLS_BUILDING_DLL
#    define GEEDTLS_API __declspec(dllexport)
#  else
#    define GEEDTLS_API __declspec(dllimport)
#  endif
#else
#  define GEEDTLS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* --- 生命周期与元信息 --- */

/* 版本 JSON：{"abi":1,"core":"0.1.5","utls":"<指纹栈版本串>"}。
 * utls 字段由二进制 build info 推导（core/version.UTLSVersion），形如
 * "refraction-networking/utls v1.8.2; bogdanfinn/fhttp v0.6.9 => ./third_party/fhttp"；
 * 取不到 build info 时为空串（历史行为），调用方须容忍。
 * 调用方负责 gtls_free_string。 */
GEEDTLS_API char *gtls_version(void);

/* 全局初始化（日志级别等），幂等。options_json 可为 NULL。 */
GEEDTLS_API int gtls_init(const char *options_json);

/* --- Client / Session --- */

/*
 * config_json: {"impersonate":"chrome_150"} 或 {"profile":{...完整 JSON...}}
 *              或 {"ja3":"..."}  仅 JA3（其余字段按引擎默认补齐并告警）
 *              或 {"ja4r":"..."} 仅 JA4R（含 cipher/扩展列表）
 *              或 {"ja4":"..."}  仅 JA4 短哈希（反查内置预设）或 JA4R 文本
 *              或 {"clienthello_hex":"..."}
 * 用户自带的指纹输入会过一遍自洽归一（pre_shared_key 占位双向约束，见
 * core/profiles/replay.go），保证"没传的部分"与引擎语义一致。
 * 返回 client handle；0 = 失败，查 gtls_last_error。
 */
GEEDTLS_API uint64_t gtls_client_new(const char *config_json);
GEEDTLS_API int      gtls_client_close(uint64_t client);

/*
 * 会话：在 client 内建独立 cookie jar / 连接缓存。session_opts_json 可为 NULL。
 * {"proxy":"http://user:pass@host:port","timeout_ms":30000,"read_timeout_ms":0,
 *  "redirect_max":10,
 *  "cookie_jar":true,"auto_decompress":true,"insecure_skip_verify":false,
 *  "proxy_from_env":true,                             // 未给 proxy 时是否读 HTTPS_PROXY/ALL_PROXY（查 NO_PROXY）
 *  "ca_bundle":"<PEM 文本 | 证书文件 | 证书目录>",     // 自持信任库，替换系统根
 *  "client_cert":"<PEM | 路径>", "client_key":"<PEM | 路径>", // mTLS；key 省略表示同文件
 *  "resolve":{"host[:port]":"1.2.3.4"},               // DNS 钉位（curl --resolve）
 *  "local_address":"192.0.2.9",                      // 出网源 IP（curl --interface 的 IP 形态）
 *  "ip_version":"4"|"6"}                             // 族偏好（curl -4/-6），省略 = 不限
 * proxy 支持的 scheme：http/https（CONNECT 隧道）、socks5、socks5h（域名交给
 * 代理解析）、socks4、socks4a。缺端口时 http/https 取 8080、socks* 取 1080。
 * socks4 只承载 IPv4（协议里目标就是 4 字节 IP），认证位只有明文 USERID——URL 里
 * 给口令会直接报错（没有可承载它的字段，不做"丢掉口令继续"的静默降级）。
 * 有代理生效时 H3/QUIC 一律不参与（QUIC 过代理需 CONNECT-UDP/RFC 9298，
 * 未实现；force_http3 + proxy 直接报 invalid 而不是偷偷直发）。
 * resolve/local_address/ip_version 只改"连到哪、从哪出去"，不改线上指纹字节：
 * SNI、Host、伪头、ClientHello 全部沿用 URL 里的原域名（钉位后连 IP 也照发 SNI）。
 * resolve 的键不做通配（钉 example.com 不连带钉 cdn.example.com）；local_address
 * 不接受网卡名；与 socks5h/socks4a/CONNECT 同用时 resolve 与 ip_version 不参与
 * （那几档由代理解析，local_address 仍然生效）。ip_version 与 local_address/resolve
 * 取值矛盾时在本函数就报 invalid_config。
 * 这三项没有接进 QUIC 拨号：force_http3 + 任一项 → 直接报 invalid（不静默换路径）。
 * session_opts_json 的协议选择（G8，2026-09-30 起）：
 *   "protocols": ["h1.1","h2"]  允许的协议集合（顺序无关）；**默认即此**（无 H3）。
 *                               ["h1.1"] 只走 H1.1、["h2"] 只走 H2（对端不支持即失败，
 *                               不静默回落）、["h3"] 会话级强制 H3。
 *   "h3": true                  protocols 的便捷写法：在默认集合上加 "h3"。
 *   h3=true 与 protocols 同时给出 ⇒ 建会话报错（不静默取其一）；h3=false 与 protocols
 *   同给是常见写法（无额外意图），不拦；开了 h3 但预设无 http3 声明也报错。
 *   请求级的 "force_http3" 语义不变（失败不回落）；默认会话下仍可用，只有会话显式
 *   限定了 protocols 且不含 h3 时才冲突报错。
 *
 * 请求头顺序与身份自洽（G9，2026-09-30 起）：
 *   "header_order": "preserve"  默认：按 profile.http1.header_order 归位（与旧行为
 *                               逐字节相同）。"input" = 按调用方传入顺序；"random" =
 *                               打乱（Host 仍在最前）。random 为了绕"顺序即信号"的
 *                               检测，与真浏览器不符且破坏可复现性，回归测试别开。
 *   "identity_sync": "auto"     默认：调用方自带 user-agent 与预设身份不一致时，把
 *                               sec-ch-ua / sec-ch-ua-platform / sec-ch-ua-mobile 校正
 *                               到该 UA，并在响应 warnings 里如实说明"TLS/JA3/JA4/H2
 *                               仍是该预设"（要字节级一致请改用同平台变体预设）。
 *                               "off" = 旧行为（不校正、不告警）。
 * tcp.mode=netstack 与 resolve 互相成全（用户态栈只吃 IPv4 字面量目标，钉位供给它，
 * 域名照旧上线）；但它的源地址由 TUN 拓扑固定，local_address 在本函数就报错而不是忽略。
 * ca_bundle 里的内容解析不出证书、或 client_cert/client_key 配不上对时，
 * 本函数直接失败（gtls_last_error 的 code=invalid_config），不会退化成
 * "用系统根继续"。
 * timeout_ms 覆盖"dial+TLS+响应头"；read_timeout_ms 是**每次 gtls_response_read**
 * 的空闲上限（0/省略 = 不限，与旧版本行为一致）。
 * 注意 config_json 与本函数的 JSON 解码都**不严格**：client config 只查六个指纹入口
 * 键，会话选项的未知键被忽略。拼错的选项（local_addr / insecure_skip_verfy）进到
 * ABI 就无声消失，所以名单校验请做在绑定层（Python/Node 各有白名单，见 docs/02）。
 */
GEEDTLS_API uint64_t gtls_session_new(uint64_t client, const char *session_opts_json);
GEEDTLS_API int      gtls_session_close(uint64_t session);

/* --- 请求与响应 --- */

/*
 * request_json: {"method":"GET","url":"https://...","headers":[["k","v"],...],
 *                "body_b64":"...", "timeout_ms":30000, "read_timeout_ms":5000,
 *                "proxy":"socks5://...", "redirect_max":10,
 *                "force_http3":false, "stream":true}
 * url 支持 https:// 与 http://（明文，G5）：明文只走 H1、不握手、SelfCheck 恒为零值，
 * force_http3 与 http:// 互斥（报 invalid_argument，不静默换路径）；
 * redirect_max <0 = 不跟随重定向（覆盖会话级；绑定层的 allow_redirects=False 用它）。
 * 返回 response handle；阻塞至响应头到达；0 = 失败（同线程查 gtls_last_error，
 * 在别的线程上发起的本调用查 gtls_error_of(session)）。
 * read_timeout_ms > 0 时覆盖会话级设置（只作用在 body 读取阶段）。
 */
GEEDTLS_API uint64_t gtls_request(uint64_t session, const char *request_json);

/*
 * 响应元信息（头到达即可用）：
 * {"status":200,"headers":[...],"used_protocol":"h2",
 *  "selfcheck":{"ja3":"...","ja4":"...","ja3_match":true,...,
 *   "ja3_fullstring":"...","sni_sent":true,"extensions":[...],
 *   "wire_extensions":[...],"grease":[...],"negotiated":{...}},
 *  "content_encoding":"gzip","decoded":true,"warnings":[...]}
 * headers 是线上原值（Content-Encoding/Content-Length 不篡改）；
 * decoded=true 时 body 读出的是解压后字节（默认开启，auto_decompress 可关）。
 */
GEEDTLS_API char *gtls_response_info(uint64_t resp);

/* 拉式流式读 body：返回读取字节数；0 = EOF；-1 = 错误。buf 由调用方分配，core 只写不持有。
 * 会话/请求设了 read_timeout_ms 时，单次读取超过该空闲上限返回 -1，
 * gtls_last_error（跨线程发起的读则用 gtls_error_of(resp)）的 code="read_timeout"；
 * 此后本次 body 只能返回同一错误，底层连接已作废（不会把调用线程永久挂住）。 */
GEEDTLS_API int64_t gtls_response_read(uint64_t resp, char *buf, int64_t buf_len);

/* 未读完即关闭 = 取消。重复 close 返回错误（不崩溃）。 */
GEEDTLS_API int gtls_response_close(uint64_t resp);

/* --- 流式上传（ABI v1 追加；H1 线上为 chunked，H2 为 DATA 帧流；H3 不支持） --- */

/*
 * 开始一次流式上传：request_json 同 gtls_request（body_b64 忽略）。
 * 返回 upload handle；0 = 失败。请求行与头部此时已发出。
 */
GEEDTLS_API uint64_t gtls_request_begin(uint64_t session, const char *request_json);

/*
 * 写一块 body（H1 = 一个 chunk 帧；H2 = DATA 流）。返回写入字节数；-1 = 错误。
 * buf_len 为 0 是 no-op（终止帧由 gtls_request_finish 发）。
 */
GEEDTLS_API int64_t gtls_request_write(uint64_t upload, const char *buf, int64_t buf_len);

/*
 * 结束 body 并阻塞至响应头到达；返回 response handle（之后与 gtls_request
 * 的返回值同样使用）；0 = 失败。无论成败，upload handle 随即失效。
 */
GEEDTLS_API uint64_t gtls_request_finish(uint64_t upload);

/* --- WebSocket（ABI v1 追加；wss://，RFC 6455；H2 上的 WS（RFC 8441）不支持） --- */

/*
 * 建立 wss 连接（走 geektls 自己的拨号 + TLS 指纹链路，Upgrade 头序受控）。
 * url_json: {"url":"wss://...","headers":[["k","v"],...],"timeout_ms":30000,
 *            "compress":false}
 *   compress=true 时握手补发 `sec-websocket-extensions: permessage-deflate`
 *   （不带参数），握手真的被接受后帧载荷自动压缩/解压（RSV1 由库管理，
 *   send/recv 收发的是明文）。默认 false：不发这个头，也不压。
 *   要精确控制 offer 参数（如 server_no_context_takeover），自己写
 *   headers 里的 sec-websocket-extensions，compress 就不是必须了。
 * 返回 ws handle；0 = 失败。
 */
GEEDTLS_API uint64_t gtls_ws_connect(uint64_t session, const char *url_json);

/* 发一帧：opcode 1=text 2=binary 8=close 9=ping 10=pong（客户端自动 masking）。
 * 0 = 成功，-1 = 失败。 */
GEEDTLS_API int gtls_ws_send(uint64_t ws, int opcode, const char *buf, int64_t buf_len);

/*
 * 收一条完整消息（分片重组；ping 自动回 pong）。timeout_ms>0 设读超时。
 * 返回消息字节数（写入 buf，opcode 经 opcode_out 返回；opcode=8 表示对端关闭）；
 * -1 = 错误（细节走 gtls_last_error）。
 */
GEEDTLS_API int64_t gtls_ws_recv(uint64_t ws, char *buf, int64_t buf_len,
                                 int timeout_ms, int *opcode_out);

/* 发 close 帧（code<=0 不带状态码）并释放 handle；0 = 成功。 */
GEEDTLS_API int gtls_ws_close(uint64_t ws, int code);

/* --- 错误与内存 --- */

/* 当前线程最近错误详情 JSON；无错误返回 "{}"。 */
GEEDTLS_API char *gtls_last_error(void);

/*
 * 指定 handle 最近一次**失败**的错误详情 JSON；无记录返回 "{}"。
 * 线程局部错误对"把阻塞调用挪到别的线程执行、回原线程再查询"的绑定
 * （Node/koffi 的 .async、Python 的 run_in_executor）是不可见的：调用在
 * worker 线程写错误，主线程查的是自己的槽。这类绑定按 handle 取即可。
 *
 * 归因规则（2026-09 修）：凡是"错误发生时手里已经有 handle"的入口，错误会**直接**
 * 记到那个 handle 上（session 上的请求/建流/WS 握手失败记 session，读 body 失败记
 * response，写/收尾失败记 upload，收发失败记 ws）。不再依赖"本线程是否 lookup
 * 过它"——此前只有本线程最近 lookup 过的那个 handle 能查到，别的都回 "{}"。
 * 关闭过的 handle 仍可查（比如 gtls_request_finish 失败即回收 upload handle，
 * 绑定正是在那一刻回头查错）；未知 / 从未失败的 handle 回 "{}"（**不是**
 * invalid_handle：绑定用 "{}" 表示"这个对象没有错误记录"，据此回落线程槽）。
 * 只读，不清空错误槽；所有权同 gtls_last_error，用 gtls_free_string 释放。
 * 本符号是 ABI 追加项：绑定必须容忍它在旧库里不存在（退化到 gtls_last_error），
 * 不能在加载阶段因为查不到它而拒绝工作。
 */
GEEDTLS_API char *gtls_error_of(uint64_t handle);

/* 释放本库返回的所有 char*；传 NULL 安全。 */
GEEDTLS_API void gtls_free_string(char *s);

/* --- 预设与自校验 --- */

/* 预设清单 JSON。 */
GEEDTLS_API char *gtls_list_presets(void);

/* 预设展开为完整 profile JSON（= 期望值，测试直接消费）。 */
GEEDTLS_API char *gtls_describe_preset(const char *name);

/*
 * 不发包，离线构造 ClientHello 并返回
 * {"ja3":...,"ja4":...,"wire_len":N,"warnings":[...]}
 * 输入为 profile JSON 或 JA3 / JA4R 字符串。
 */
GEEDTLS_API char *gtls_check_profile(const char *profile_json_or_ja3_or_ja4r);

#ifdef __cplusplus
}
#endif

#endif /* GEEDTLS_H */
