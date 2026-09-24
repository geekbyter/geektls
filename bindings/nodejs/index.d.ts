// geektls Node.js 绑定类型声明（与 index.js 对齐）。

declare module 'geektls' {
  export interface VersionInfo {
    abi: number;
    core: string;
    utls: string;
  }

  export interface SelfCheck {
    ja3: string;
    ja3_hash: string;
    ja4: string;
    ja3_match?: boolean;
    ja4_match?: boolean;
  }

  export interface SessionOptions {
    impersonate?: string;
    profile?: object;
    ja3?: string;
    ja4r?: string;
    clienthello_hex?: string;
    proxy?: string;
    timeoutMs?: number;
    redirectMax?: number;
    cookieJar?: boolean;
    insecureSkipVerify?: boolean;
  }

  export interface RequestOptions {
    method?: string;
    url: string;
    headers?: Record<string, string> | [string, string][];
    body?: string | Buffer | Uint8Array;
    timeoutMs?: number;
    proxy?: string;
    forceHttp3?: boolean;
    stream?: boolean;
  }

  export class GeekTLSError extends Error {
    code: string;
  }

  export class Response {
    status: number;
    headers: [string, string][];
    usedProtocol: string;
    selfcheck: SelfCheck;
    readonly body: NodeJS.ReadableStream;
    read(): Promise<Buffer>;
    text(): Promise<string>;
    json<T = unknown>(): Promise<T>;
    close(): Promise<void>;
  }

  export class Session {
    constructor(options?: SessionOptions);
    request(req: RequestOptions): Promise<Response>;
    get(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    post(url: string, options?: Omit<RequestOptions, 'url' | 'method'>): Promise<Response>;
    close(): void;
  }

  export function version(): VersionInfo;
  export function init(options?: object): void;
  export function lastError(): { code?: string; message?: string };
  export function listPresets(): string[];
  export function describePreset(name: string): object;
  export function checkProfile(input: string | object): object;
}
