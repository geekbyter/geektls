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

/** 离线构造 ClientHello 自校验（profile JSON / ja3 / ja4r / hex 入参）。 */
function checkProfile(input) {
  const raw = gtls_check_profile(typeof input === 'string' ? input : JSON.stringify(input));
  if (raw == null) raiseLastError();
  return JSON.parse(raw);
}

class Response {
  constructor(handle) {
    this._handle = handle;
    const info = gtls_response_info(handle);
    if (info == null) {
      gtls_response_close(handle);
      raiseLastError();
    }
    const parsed = JSON.parse(info);
    this.status = parsed.status;
    this.headers = parsed.headers || [];
    this.usedProtocol = parsed.used_protocol || '';
    this.selfcheck = parsed.selfcheck || {};
    this._body = null;
  }

  /** Node Readable 流式 body（内部循环 gtls_response_read）。 */
  get body() {
    if (this._body === null) {
      this._body = new ResponseBody(this._handle);
    }
    return this._body;
  }

  /** 一次性读完。 */
  async read() {
    const chunks = [];
    for await (const chunk of this.body) chunks.push(chunk);
    return Buffer.concat(chunks);
  }

  async text() {
    return (await this.read()).toString('utf-8');
  }

  async json() {
    return JSON.parse(await this.text());
  }

  async close() {
    if (this._handle) {
      gtls_response_close(this._handle);
      this._handle = 0n;
    }
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

/**
 * 指纹伪造会话。options: {impersonate|profile|ja3|ja4r|clienthello_hex,
 * proxy, timeoutMs, redirectMax, cookieJar, insecureSkipVerify}
 */
class Session {
  constructor(options = {}) {
    const { proxy, timeoutMs, redirectMax, cookieJar, insecureSkipVerify, ...config } = options;
    this._client = gtls_client_new(JSON.stringify(config));
    if (!this._client) raiseLastError();
    this._session = 0n;
    try {
      const opts = {};
      if (proxy !== undefined) opts.proxy = proxy;
      if (timeoutMs !== undefined) opts.timeout_ms = timeoutMs;
      if (redirectMax !== undefined) opts.redirect_max = redirectMax;
      if (cookieJar !== undefined) opts.cookie_jar = cookieJar;
      if (insecureSkipVerify !== undefined) opts.insecure_skip_verify = insecureSkipVerify;
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
   * req: {method, url, headers, body, timeoutMs, proxy, forceHttp3, stream}
   * headers: {k:v} 或 [[k,v],...]；body: string|Buffer|Uint8Array
   */
  async request(req) {
    const payload = { method: req.method || 'GET', url: req.url };
    if (req.headers) {
      payload.headers = Array.isArray(req.headers)
        ? req.headers
        : Object.entries(req.headers);
    }
    if (req.body != null) {
      payload.body_b64 = Buffer.from(req.body).toString('base64');
    }
    if (req.timeoutMs) payload.timeout_ms = req.timeoutMs;
    if (req.proxy) payload.proxy = req.proxy;
    if (req.forceHttp3) payload.force_http3 = true;
    if (req.stream !== undefined) payload.stream = req.stream;

    const handle = await callAsync(gtls_request, this._session, JSON.stringify(payload));
    if (!handle) raiseLastError();
    return new Response(handle);
  }

  get(url, options = {}) {
    return this.request({ method: 'GET', url, ...options });
  }

  post(url, options = {}) {
    return this.request({ method: 'POST', url, ...options });
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
