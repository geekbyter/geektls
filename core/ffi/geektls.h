/*
 * geektls.h — geektls core C ABI v1（手写维护的权威契约，实现见 core/ffi/exports.go）。
 *
 * 规则摘要（完整契约见 docs/02-ffi-abi.md）：
 *   - JSON 进、JSON 出；handle 为 uint64_t，0 表示无效/失败。
 *   - 返回 char* 的函数把内存所有权移交调用方，必须用 gtls_free_string() 释放；
 *     返回 NULL 表示失败，错误详情取 gtls_last_error()。
 *   - 返回 int 的函数：0 = 成功，-1 = 失败（细节同样走 gtls_last_error）。
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

/* 版本 JSON：{"abi":1,"core":"0.1.5","utls":""}。调用方负责 gtls_free_string。 */
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

/* 会话：在 client 内建独立 cookie jar / 连接缓存。session_opts_json 可为 NULL。 */
GEEDTLS_API uint64_t gtls_session_new(uint64_t client, const char *session_opts_json);
GEEDTLS_API int      gtls_session_close(uint64_t session);

/* --- 请求与响应 --- */

/*
 * request_json: {"method":"GET","url":"https://...","headers":[["k","v"],...],
 *                "body_b64":"...", "timeout_ms":30000, "proxy":"socks5://...",
 *                "force_http3":false, "stream":true}
 * 返回 response handle；阻塞至响应头到达；0 = 失败。
 */
GEEDTLS_API uint64_t gtls_request(uint64_t session, const char *request_json);

/*
 * 响应元信息（头到达即可用）：
 * {"status":200,"headers":[...],"used_protocol":"h2",
 *  "selfcheck":{"ja3":"...","ja4":"...","ja3_match":true,...,
 *   "ja3_fullstring":"...","sni_sent":true,"extensions":[...],
 *   "wire_extensions":[...],"grease":[...],"negotiated":{...}}}
 */
GEEDTLS_API char *gtls_response_info(uint64_t resp);

/* 拉式流式读 body：返回读取字节数；0 = EOF；-1 = 错误。buf 由调用方分配，core 只写不持有。 */
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

/* --- 错误与内存 --- */

/* 当前线程最近错误详情 JSON；无错误返回 "{}"。 */
GEEDTLS_API char *gtls_last_error(void);

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
