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

  export interface SessionOptions {
    impersonate?: string;
    profile?: object;
    ja3?: string;
    ja4r?: string;
    clienthello_hex?: string;
    // 引擎字段
    proxy?: string;
    timeoutMs?: number;
    redirectMax?: number;
    cookieJar?: boolean;
    insecureSkipVerify?: boolean;
    // requests 风格别名
    headers?: Record<string, string> | [string, string][];
    proxies?: string | Record<string, string>;
    timeout?: number;
    verify?: boolean;
    allowRedirects?: boolean;
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
    proxy?: string;
    forceHttp3?: boolean;
    stream?: boolean;
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
    close(): void;
  }

  export function version(): VersionInfo;
  export function init(options?: object): void;
  export function lastError(): { code?: string; message?: string };
  export function listPresets(): string[];
  export function describePreset(name: string): object;
  export function checkProfile(input: string | object): object;
}
