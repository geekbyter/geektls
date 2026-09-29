'use strict';

/**
 * geektls Node.js 绑定（koffi，无 node-gyp）。
 *
 * P5 全量：Session（Promise API）+ Response（Node Readable 流式 body）。
 *
 * 内存约定（docs/02-ffi-abi.md §2）：core 返回的 char* 所有权移交调用方；
 * 用 koffi disposable type 声明，转 JS 字符串后自动回调 gtls_free_string。
 *
 * 异步模型：gtls_request / gtls_response_read 是阻塞调用，经 koffi 的
 * `.async`（worker 线程执行 FFI、回调回主线程）包成 Promise，不阻塞事件循环。
 * handle 生命周期（new/close/info）是微秒级调用，保持同步。
 *
 * 加载搜索顺序：环境变量 GEEDTLS_LIB → 包内 → 仓库 build/ 目录 → 系统路径。
 */

const path = require('node:path');
const { Readable } = require('node:stream');
const koffi = require('koffi');

function libNames() {
  switch (process.platform) {
    case 'win32':
      return ['geektls.dll'];
    case 'darwin':
      return ['libgeektls.dylib'];
    default:
      return ['libgeektls.so'];
  }
}

function* candidatePaths() {
  if (process.env.GEEDTLS_LIB) yield process.env.GEEDTLS_LIB;
  for (const name of libNames()) {
    yield path.join(__dirname, name); // 包内分发
    yield path.join(__dirname, '..', '..', 'build', name); // 仓库开发态
  }
  for (const name of libNames()) yield name; // 加载器默认搜索路径
}

function loadLibrary() {
  const errors = [];
  for (const p of candidatePaths()) {
    try {
      return koffi.load(p);
    } catch (err) {
      errors.push(`  ${p}: ${err.message}`);
    }
  }
  throw new Error(
    'cannot load the geektls core library; set GEEDTLS_LIB to its path. Tried:\n' +
      errors.join('\n')
  );
}

const lib = loadLibrary();

// --- 函数声明（与 core/ffi/geektls.h 对齐） ---

const gtls_free_string = lib.func('void gtls_free_string(void *s)');

// C 侧签名是 char*；disposable 让 koffi 转字符串后自动调 gtls_free_string。
const GtlsStr = koffi.disposable('GtlsStr', 'str', (ptr) => gtls_free_string(ptr));

const gtls_version = lib.func('GtlsStr gtls_version(void)');
const gtls_init = lib.func('int gtls_init(const char *options_json)');
const gtls_last_error = lib.func('GtlsStr gtls_last_error(void)');
const gtls_client_new = lib.func('uint64_t gtls_client_new(const char *config_json)');
const gtls_client_close = lib.func('int gtls_client_close(uint64_t client)');
const gtls_session_new = lib.func(
  'uint64_t gtls_session_new(uint64_t client, const char *session_opts_json)'
);
const gtls_session_close = lib.func('int gtls_session_close(uint64_t session)');
const gtls_request = lib.func('uint64_t gtls_request(uint64_t session, const char *request_json)');
const gtls_response_info = lib.func('GtlsStr gtls_response_info(uint64_t resp)');
const gtls_response_read = lib.func(
  'int64_t gtls_response_read(uint64_t resp, void *buf, int64_t buf_len)'
);
const gtls_response_close = lib.func('int gtls_response_close(uint64_t resp)');
const gtls_request_begin = lib.func(
  'uint64_t gtls_request_begin(uint64_t session, const char *request_json)'
);
const gtls_request_write = lib.func(
  'int64_t gtls_request_write(uint64_t upload, const void *buf, int64_t buf_len)'
);
const gtls_request_finish = lib.func('uint64_t gtls_request_finish(uint64_t upload)');
const gtls_list_presets = lib.func('GtlsStr gtls_list_presets(void)');
const gtls_describe_preset = lib.func('GtlsStr gtls_describe_preset(const char *name)');
const gtls_check_profile = lib.func('GtlsStr gtls_check_profile(const char *input)');

class GeekTLSError extends Error {
  constructor(code, message) {
    super(`[${code}] ${message}`);
    this.name = 'GeekTLSError';
    this.code = code;
  }
}

function lastError() {
  return JSON.parse(gtls_last_error() || '{}');
}

function raiseLastError() {
  const err = lastError();
  throw new GeekTLSError(err.code || 'unknown', err.message || 'ffi call failed without detail');
}

// callAsync 把阻塞 FFI 调用放到 koffi worker 线程，Promise 化。
function callAsync(fn, ...args) {
  return new Promise((resolve, reject) => {
    fn.async(...args, (err, res) => (err ? reject(err) : resolve(res)));
  });
}

const EXPECTED_ABI = 1;

/** 返回 {abi, core, utls} 并核对 ABI 主版本（防绑定与动态库错配）。 */
function version() {
  const raw = gtls_version();
  if (raw == null) raiseLastError();
  const v = JSON.parse(raw);
  if (v.abi !== EXPECTED_ABI) {
    throw new Error(`geektls ABI mismatch: binding expects ${EXPECTED_ABI}, core exports ${v.abi}`);
  }
  return v;
}

/** 全局初始化（幂等）。 */
function init(options = {}) {
  if (gtls_init(JSON.stringify(options)) !== 0) raiseLastError();
}

/** 内置预设清单。 */
function listPresets() {
  return JSON.parse(gtls_list_presets() || '[]');
}

/** 预设展开为完整 profile JSON（= 期望值）。 */
function describePreset(name) {
  const raw = gtls_describe_preset(name);
  if (raw == null) raiseLastError();
  return JSON.parse(raw);
}

/** 离线构造 ClientHello 自校验（profile JSON / ja3 / ja4 / ja4r / hex 入参）。 */
function checkProfile(input) {
  const raw = gtls_check_profile(typeof input === 'string' ? input : JSON.stringify(input));
  if (raw == null) raiseLastError();
  return JSON.parse(raw);
}

// ---- 响应读取辅助（与 Go / Python 绑定同一套语义）----

/** 状态码 → reason（RFC 9110 常见短语；引擎不上报服务端原文，这里本地映射）。 */
const REASON = {
  100: 'Continue', 101: 'Switching Protocols',
  200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content', 206: 'Partial Content',
  301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 304: 'Not Modified',
  307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
  405: 'Method Not Allowed', 406: 'Not Acceptable', 408: 'Request Timeout',
  409: 'Conflict', 410: 'Gone', 413: 'Payload Too Large', 415: 'Unsupported Media Type',
  418: "I'm a teapot", 422: 'Unprocessable Entity', 429: 'Too Many Requests',
  500: 'Internal Server Error', 501: 'Not Implemented', 502: 'Bad Gateway',
  503: 'Service Unavailable', 504: 'Gateway Timeout',
};

/** 从 Content-Type 提取 charset；没有则返回 undefined。 */
function parseCharset(contentType) {
  if (!contentType) return undefined;
  for (const part of String(contentType).split(';').slice(1)) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    if (part.slice(0, idx).trim().toLowerCase() === 'charset') {
      return part.slice(idx + 1).trim().replace(/^["']|["']$/g, '') || undefined;
    }
  }
  return undefined;
}

/** 大小写不敏感取头（与 Go 的 Header(name)、Python 的 headers[...] 对齐）。 */
function headerOf(headers, name) {
  const lower = String(name).toLowerCase();
  for (const [k, v] of headers) {
    if (String(k).toLowerCase() === lower) return v;
  }
  return undefined;
}

/**
 * 按 charset 解码；未声明时依次尝试 utf-8 → gb18030 → latin-1
 * （Node 内置 TextDecoder 支持 gb18030，无需额外依赖）。
 */
function decodeBytes(buf, encoding) {
  if (encoding) {
    try {
      return new TextDecoder(encoding).decode(buf);
    } catch {
      /* 未识别的编码名，继续用探测 */
    }
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    /* 不是合法 utf-8 */
  }
  try {
    return new TextDecoder('gb18030').decode(buf);
  } catch {
    return buf.toString('latin1');
  }
}

class Response {
  constructor(handle, { method, url, elapsedMs } = {}) {
    this._handle = handle;
    const info = gtls_response_info(handle);
    if (info == null) {
      gtls_response_close(handle);
      raiseLastError();
    }
    const parsed = JSON.parse(info);
    this.status = parsed.status;
    this.statusCode = parsed.status; // 与 Python/Go 命名对齐
    this.headers = parsed.headers || []; // 原始 [[k,v],...]（保兼容）
    this.usedProtocol = parsed.used_protocol || '';
    this.httpVersion = this.usedProtocol;
    this.selfcheck = parsed.selfcheck || {};
    this.method = method;
    this.url = url;
    this.elapsed = elapsedMs;
    this._body = null;
    this._content = null;
    this._json = null;
  }

  /** 4xx/5xx 之外为 true（requests 语义）。 */
  get ok() {
    return this.status < 400;
  }

  get reason() {
    return REASON[this.status] || '';
  }

  /** 大小写不敏感取单个响应头值。 */
  header(name) {
    return headerOf(this.headers, name);
  }

  /** Content-Type 声明的编码（未声明为 undefined）。 */
  get encoding() {
    return parseCharset(this.header('content-type'));
  }

  /** 显然没声明 charset 时的探测结果。 */
  get apparentEncoding() {
    if (this.encoding) return this.encoding;
    if (this._content) {
      try {
        new TextDecoder('utf-8', { fatal: true }).decode(this._content);
        return 'utf-8';
      } catch {
        return 'gb18030';
      }
    }
    return 'utf-8';
  }

  /** Node Readable 流式 body（内部循环 gtls_response_read）。 */
  get body() {
    if (this._body === null) {
      this._body = new ResponseBody(this._handle);
    }
    return this._body;
  }

  /** 一次性读完（缓存，与 Python 的 .content 语义一致）。 */
  async read() {
    if (this._content !== null) return this._content;
    const chunks = [];
    for await (const chunk of this.body) chunks.push(chunk);
    this._content = Buffer.concat(chunks);
    return this._content;
  }

  /** 流式块（等价 Python 的 iter_content；chunkSize 需在 body 首次使用前指定）。 */
  async *iterContent(chunkSize) {
    const stream = chunkSize ? new ResponseBody(this._handle, chunkSize) : this.body;
    for await (const chunk of stream) yield chunk;
  }

  /** 按行流式（保留行尾换行符）。 */
  async *iterLines(chunkSize) {
    let pending = Buffer.alloc(0);
    for await (const chunk of this.iterContent(chunkSize)) {
      pending = Buffer.concat([pending, chunk]);
      let idx;
      while ((idx = pending.indexOf(0x0a)) >= 0) {
        const line = pending.subarray(0, idx + 1);
        pending = pending.subarray(idx + 1);
        yield line;
      }
    }
    if (pending.length) yield pending;
  }

  /** body 字节（等价 Python 的 .content）。 */
  async bytes() {
    return this.read();
  }

  /** body 文本（按 charset 解码，未声明时自动探测，避免中文乱码）。 */
  async text() {
    return decodeBytes(await this.read(), this.encoding);
  }

  /** body JSON（按 charset 解码，兼容 BOM；结果缓存）。 */
  async json() {
    if (this._json === null) {
      const text = (await this.text()).replace(/^\ufeff/, '');
      this._json = JSON.parse(text);
    }
    return this._json;
  }

  /** >=400 时抛 GeekTLSError（异常上挂 .response）。 */
  raiseForStatus() {
    if (!this.ok) {
      const err = new GeekTLSError('http_error', `${this.status} ${this.reason || 'HTTP error'}`);
      err.response = this;
      throw err;
    }
  }

  async close() {
    if (this._handle) {
      gtls_response_close(this._handle);
      this._handle = 0n;
    }
  }

  toString() {
    return `<Response [${this.status}] ${this.usedProtocol || '-'}>`;
  }
}

class ResponseBody extends Readable {
  constructor(handle, chunkSize = 65536) {
    super();
    this._handle = handle;
    this._chunkSize = chunkSize;
    this._buf = Buffer.allocUnsafe(chunkSize);
    this._done = false;
  }

  _read() {
    if (this._done) return;
    // setImmediate 关键：koffi 的 .async 不能在其自身异步回调的同一回合里
    // 对同一函数再次发起（会静默死锁，实测）。把下一次读挪出回调回合。
    setImmediate(async () => {
      try {
        const raw = await callAsync(gtls_response_read, this._handle, this._buf, BigInt(this._chunkSize));
        const n = Number(raw); // koffi int64 返回值可能是 Number 或 BigInt
        if (n < 0) {
          const err = lastError();
          this.destroy(new GeekTLSError(err.code || 'read_failed', err.message || 'read failed'));
          return;
        }
        if (n === 0) {
          this._done = true;
          this.push(null);
          return;
        }
        this.push(Buffer.from(this._buf.subarray(0, n)));
      } catch (err) {
        this.destroy(err);
      }
    });
  }

  _destroy(err, cb) {
    if (this._done || this._handle) {
      gtls_response_close(this._handle);
      this._handle = 0n;
    }
    cb(err);
  }
}

/** 从 requests 风格 proxies（对象/字符串）里取出一个代理 URL。 */
function pickProxy(proxies) {
  if (!proxies) return undefined;
  if (typeof proxies === 'string') return proxies;
  return proxies.https || proxies.http || proxies.all || Object.values(proxies)[0];
}

/**
 * 指纹伪造会话。options:
 * - 引擎字段：{impersonate|profile|ja3|ja4|ja4r|clienthello_hex, proxy, timeoutMs,
 *             redirectMax, cookieJar, insecureSkipVerify}
 * - requests 风格别名（与 Python 绑定一致）：{headers（会话默认头）, proxies, timeout（秒）,
 *             verify:false, allowRedirects:false}
 */
class Session {
  constructor(options = {}) {
    const {
      proxy, proxies, timeoutMs, timeout, redirectMax, allowRedirects,
      cookieJar, insecureSkipVerify, verify, headers, ...config
    } = options;
    this._headers = headers
      ? Object.entries(Array.isArray(headers) ? Object.fromEntries(headers) : headers)
      : [];
    this._client = gtls_client_new(JSON.stringify(config));
    if (!this._client) raiseLastError();
    this._session = 0n;
    try {
      const opts = {};
      const proxyURL = proxy !== undefined ? proxy : pickProxy(proxies);
      if (proxyURL !== undefined) opts.proxy = proxyURL;
      if (timeoutMs !== undefined) opts.timeout_ms = timeoutMs;
      else if (timeout !== undefined) opts.timeout_ms = Math.round(timeout * 1000);
      if (redirectMax !== undefined) opts.redirect_max = redirectMax;
      else if (allowRedirects === false) opts.redirect_max = -1;
      if (cookieJar !== undefined) opts.cookie_jar = cookieJar;
      if (insecureSkipVerify !== undefined) opts.insecure_skip_verify = insecureSkipVerify;
      else if (verify === false) opts.insecure_skip_verify = true;
      this._session = gtls_session_new(this._client, JSON.stringify(opts));
      if (!this._session) raiseLastError();
    } catch (err) {
      gtls_client_close(this._client);
      this._client = 0n;
      throw err;
    }
  }

  /**
   * 发请求（Promise 化，不阻塞事件循环）。
   * 请求级字段：{method, url, headers, params, data, json, body, timeoutMs, timeout,
   *             proxy, forceHttp3, stream}
   * - headers: {k:v} 或 [[k,v],...]（会与会话级默认头合并）
   * - params: 对象/[[k,v]]/查询串 → 拼到 URL
   * - data: 对象 → 表单编码；string/Buffer → 原样
   * - json: 任意可序列化值 → JSON body（自动补 content-type）
   * - timeout: 秒（与 Python 绑定一致）；timeoutMs: 毫秒
   */
  async request(req) {
    const method = (req.method || 'GET').toUpperCase();
    let url = req.url;
    if (req.params) {
      const qs =
        typeof req.params === 'string'
          ? req.params.replace(/^\?/, '')
          : new URLSearchParams(req.params).toString();
      if (qs) url += (url.includes('?') ? '&' : '?') + qs;
    }

    const headers = [...(this._headers || [])];
    const addHeader = (k, v) => headers.push([k, v]);
    const hasHeader = (name) => headerOf(headers, name) !== undefined;
    if (req.headers) {
      for (const [k, v] of Array.isArray(req.headers)
        ? req.headers
        : Object.entries(req.headers)) {
        addHeader(k, v);
      }
    }

    const payload = { method, url };
    let raw = null;
    if (req.json !== undefined) {
      raw = Buffer.from(JSON.stringify(req.json));
      if (!hasHeader('content-type')) addHeader('content-type', 'application/json');
    } else if (req.data !== undefined) {
      if (req.data !== null && typeof req.data === 'object' && !Buffer.isBuffer(req.data) &&
          !(req.data instanceof Uint8Array)) {
        raw = Buffer.from(new URLSearchParams(req.data).toString());
        if (!hasHeader('content-type')) {
          addHeader('content-type', 'application/x-www-form-urlencoded');
        }
      } else {
        raw = Buffer.from(req.data);
      }
    } else if (req.body != null &&
               (typeof req.body === 'string' || Buffer.isBuffer(req.body) ||
                req.body instanceof Uint8Array)) {
      raw = Buffer.from(req.body);
    }
    if (raw !== null) payload.body_b64 = raw.toString('base64');
    if (headers.length) payload.headers = headers;

    if (req.timeoutMs !== undefined) payload.timeout_ms = req.timeoutMs;
    else if (req.timeout !== undefined) payload.timeout_ms = Math.round(req.timeout * 1000);
    if (req.proxy) payload.proxy = req.proxy;
    if (req.forceHttp3) payload.force_http3 = true;
    if (req.stream !== undefined) payload.stream = req.stream;

    // 迭代器/AsyncIterable body → chunked 流式上传（H1 chunked / H2 DATA 帧流）
    const streamChunks =
      raw === null && req.body != null &&
      (typeof req.body[Symbol.asyncIterator] === 'function' ||
        typeof req.body[Symbol.iterator] === 'function')
        ? req.body
        : null;

    const started = Date.now();
    if (streamChunks) {
      return this._streamUpload(payload, streamChunks, { method, url, started });
    }
    const handle = await callAsync(gtls_request, this._session, JSON.stringify(payload));
    if (!handle) raiseLastError();
    return new Response(handle, { method, url, elapsedMs: Date.now() - started });
  }

  /** 迭代器 body 的流式上传：begin → 逐块 write → finish 收响应头。 */
  async _streamUpload(payload, chunks, { method, url, started }) {
    const up = await callAsync(gtls_request_begin, this._session, JSON.stringify(payload));
    if (!up) raiseLastError();
    try {
      for await (const chunk of chunks) {
        const buf = typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.from(chunk);
        if (!buf.length) continue;
        const n = await callAsync(gtls_request_write, up, buf, BigInt(buf.length));
        if (Number(n) < 0) raiseLastError();
      }
    } catch (err) {
      try { await callAsync(gtls_request_finish, up); } catch { /* 回收 handle 即可 */ }
      throw err;
    }
    const handle = await callAsync(gtls_request_finish, up);
    if (!handle) raiseLastError();
    return new Response(handle, { method, url, elapsedMs: Date.now() - started });
  }

  get(url, options = {}) {
    return this.request({ method: 'GET', url, ...options });
  }

  post(url, options = {}) {
    return this.request({ method: 'POST', url, ...options });
  }

  put(url, options = {}) {
    return this.request({ method: 'PUT', url, ...options });
  }

  patch(url, options = {}) {
    return this.request({ method: 'PATCH', url, ...options });
  }

  delete(url, options = {}) {
    return this.request({ method: 'DELETE', url, ...options });
  }

  head(url, options = {}) {
    return this.request({ method: 'HEAD', url, ...options });
  }

  options(url, options = {}) {
    return this.request({ method: 'OPTIONS', url, ...options });
  }

  close() {
    if (this._session) {
      gtls_session_close(this._session);
      this._session = 0n;
    }
    if (this._client) {
      gtls_client_close(this._client);
      this._client = 0n;
    }
  }
}

module.exports = {
  Session,
  Response,
  version,
  init,
  lastError,
  listPresets,
  describePreset,
  checkProfile,
  GeekTLSError,
};
