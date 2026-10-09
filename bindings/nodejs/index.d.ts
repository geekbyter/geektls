// geektls Node.js 绑定类型声明（与 index.js 对齐）。

declare module 'geektls' {
  export interface VersionInfo {
    abi: number;
    core: string;
    utls: string;
  }

  export interface GreaseMark {
    where: 'cipher' | 'extension' | 'group' | 'version' | 'key_share';
    index: number;
    value: number;
  }

  export interface SelfCheck {
    ja3: string;
    ja3_hash: string;
    ja4: string;
    ja3_match?: boolean;
    ja4_match?: boolean;
    /** 与 ja3 同值（显式名） */
    ja3_fullstring?: string;
    /** SNI 实际上链与否（IP 字面量目标线上省略） */
    sni_sent?: boolean;
    /** 线上扩展序（剔 GREASE） */
    extensions?: number[];
    /** 线上扩展序（含 GREASE 实际值） */
    wire_extensions?: number[];
    grease?: GreaseMark[];
    /** 握手协商结果（hex 串） */
    negotiated?: { cipher: string; version: string; alpn: string };
  }

  /** 证书 / 私钥 / CA 的取值形态：文件路径、含 .pem/.crt/.cer 的目录、或内联 PEM 文本 */
  export type PemOrPath = string | Buffer | Uint8Array;

  export interface SessionOptions {
    impersonate?: string;
    profile?: object;
    ja3?: string;
    ja4?: string;
    ja4r?: string;
    clienthello_hex?: string;
    // 引擎字段（运行时也接受这些字段的 JSON 原名，如 timeout_ms /
    // insecure_skip_verify / resolve；类型上请用下面的驼峰名。两个名单之外的键
    // 会抛 TypeError——core 的 JSON 解码不严格，未知键会静默失效，所以在绑定层拦）
    proxy?: string;
    /** 未给 proxy 时是否读 HTTPS_PROXY / ALL_PROXY（并查 NO_PROXY）。默认 true */
    proxyFromEnv?: boolean;
    timeoutMs?: number;
    /** body 单次读取的空闲上限（毫秒）；0/省略 = 不限。超时抛 GeekTLSError(code='read_timeout') */
    readTimeoutMs?: number;
    redirectMax?: number;
    cookieJar?: boolean;
    insecureSkipVerify?: boolean;
    /** 自持信任库（替换系统根）：路径 / 目录 / PEM 文本 */
    caBundle?: PemOrPath;
    /** mTLS 客户端证书：路径 / PEM（证书+私钥可同文件）/ [证书, 私钥] / {cert, key} */
    cert?: PemOrPath | [PemOrPath, PemOrPath?] | { cert?: PemOrPath; key?: PemOrPath };
    /** cert 的私钥段（单独给定时覆盖 cert 元组 / 对象里的 key） */
    certKey?: PemOrPath;
    /** DNS 钉位（curl --resolve）：{'host:port': ip | 'host': ip}；键不做通配 */
    resolve?: Record<string, string>;
    /** 出网源 IP（curl --interface 的 IP 形态；网卡名不支持） */
    localAddress?: string;
    /** 协议族偏好：'4' | '6'（curl -4/-6）；省略 = 不限 */
    ipVersion?: string | number;
    // requests 风格别名
    headers?: Record<string, string> | [string, string][];
    proxies?: string | Record<string, string>;
    timeout?: number;
    /** 秒：body 单次读取的空闲上限（映射到 read_timeout_ms） */
    readTimeout?: number;
    /** true（默认，系统信任库）/ false（跳过校验）/ CA bundle 路径或 PEM 文本 */
    verify?: boolean | PemOrPath;
    allowRedirects?: boolean;
    /** 响应透明解压开关（默认 true） */
    autoDecompress?: boolean;
    /** requests 同名别名：false = 不读代理环境变量（映射到 proxyFromEnv） */
    trustEnv?: boolean;
  }

  export interface RequestOptions {
    method?: string;
    url: string;
    /** 追加/覆盖会话默认头（大小写不敏感合并） */
    headers?: Record<string, string> | [string, string][];
    /** 查询参数：对象 / [[k,v]] / 查询串 */
    params?: Record<string, unknown> | [string, string][] | string;
    /** 表单（对象→urlencoded）或原始字节 */
    data?: Record<string, unknown> | string | Buffer | Uint8Array;
    /** JSON body（自动补 content-type） */
    json?: unknown;
    /** 原始 body；传 Iterable/AsyncIterable 则走 chunked 流式上传（H1 chunked / H2 DATA） */
    body?: string | Buffer | Uint8Array | Iterable<string | Buffer | Uint8Array> | AsyncIterable<string | Buffer | Uint8Array>;
    timeoutMs?: number;
    /** 秒（与 Python 绑定一致） */
    timeout?: number;
    /** body 单次读取的空闲上限（毫秒），覆盖会话级 readTimeoutMs */
    readTimeoutMs?: number;
    /** 秒 */
    readTimeout?: number;
    proxy?: string;
    forceHttp3?: boolean;
    stream?: boolean;
    /** 请求级覆盖透明解压开关 */
    autoDecompress?: boolean;
  }

  export class GeekTLSError extends Error {
    code: string;
    /** raiseForStatus() 抛出时挂在异常上的响应对象 */
    response?: Response;
  }

  export class Response {
    status: number;
    /** 与 status 等值（跨语言命名对齐） */
    statusCode: number;
    /** 4xx/5xx 之外为 true */
    readonly ok: boolean;
    /** 状态码短语（RFC 9110 本地映射） */
    readonly reason: string;
    /** 原始 [[k, v], ...]（保兼容；取头请用 header()） */
    headers: [string, string][];
    usedProtocol: string;
    httpVersion: string;
    selfcheck: SelfCheck;
    /** 线上 Content-Encoding 原值（T-DECOMP） */
    contentEncoding: string;
    /** true = body 已透明解压 */
    decoded: boolean;
    /** 未知编码透传等告警 */
    warnings: string[];
    method?: string;
    url?: string;
    elapsed?: number;
    /** Content-Type 声明的编码（未声明为 undefined） */
    readonly encoding: string | undefined;
    /** 无声明时的探测结果（utf-8 → gb18030） */
    readonly apparentEncoding: string;
    /** Node Readable 流式 body */
    readonly body: NodeJS.ReadableStream;
    /** 大小写不敏感取单个响应头 */
    header(name: string): string | undefined;
    read(): Promise<Buffer>;
    bytes(): Promise<Buffer>;
    text(): Promise<string>;
    json<T = unknown>(): Promise<T>;
    iterContent(chunkSize?: number): AsyncGenerator<Buffer>;
    iterLines(chunkSize?: number): AsyncGenerator<Buffer>;
    /** >=400 时抛 GeekTLSError（异常上挂 .response） */
    raiseForStatus(): void;
    close(): Promise<void>;
    toString(): string;
  }

  /**
   * WebSocket（wss://，RFC 6455；拉模型）。握手协商成 permessage-deflate 时，
   * send/recv 收发的仍是明文——压缩与 RSV1 位在库里透明完成。
   */
  export class WebSocket {
    static readonly OP_TEXT: 1;
    static readonly OP_BINARY: 2;
    static readonly OP_CLOSE: 8;
    static readonly OP_PING: 9;
    static readonly OP_PONG: 10;
    send(data: string | Buffer | Uint8Array, opcode?: number): Promise<void>;
    recv(timeoutMs?: number, bufSize?: number): Promise<{ opcode: number; data: Buffer }>;
    recvText(timeoutMs?: number): Promise<string>;
    close(code?: number): Promise<void>;
  }

  export class Session {
    constructor(options?: SessionOptions);
    request(req: RequestOptions): Promise<Response>;
    get(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    post(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    put(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    patch(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    delete(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    head(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    options(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    /**
     * 建立 wss:// 连接。compress=true 时握手 offer `permessage-deflate`（RFC 7692），
     * 服务端接受后 send/recv 仍是明文（RSV1 由库管理）。精确控制 offer 参数请把
     * sec-websocket-extensions 写进 headers。
     */
    websocket(
      url: string,
      options?: { headers?: Record<string, string> | [string, string][]; timeoutMs?: number; timeout?: number; compress?: boolean }
    ): Promise<WebSocket>;
    close(): void;
  }

  export function version(): VersionInfo;
  export function init(options?: object): void;
  export function lastError(): { code?: string; message?: string };
  /** 按 handle 取最近一次失败的错误（跨线程回收，见 core/ffi/geektls.h）。 */
  export function errorOf(handle: number | bigint): { code?: string; message?: string };
  export function listPresets(): string[];
  export function describePreset(name: string): object;
  export function checkProfile(input: string | object): object;
  /** v0.2.0: pcap/pcapng -> E1p records（与 CLI import-pcap 同核）。records 空 = 全拒（见 skipped）。 */
  export function importPcap(opts: {
    path?: string;
    data?: Buffer | Uint8Array;
    stream?: number;
    all?: boolean;
    tcpOnly?: boolean;
    ua?: string;
    name?: string;
    sourceBase?: string;
  }): { records: object[]; skipped: string[] };

  /** 模块级共享默认会话：首次调用可传 Session options 配置，之后只读 */
  export function defaultSession(options?: object): Session;
  export function request(req: RequestOptions): Promise<Response>;
  export function get(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
  export function head(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
  export function post(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
  export function put(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
  export function patch(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
  /** `delete` 是 JS 保留字，模块级用 `del`（Session.delete 不受影响） */
  export function del(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
  export function options(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
}
