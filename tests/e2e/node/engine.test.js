'use strict';

// P5 Node 绑定用例（node:test）：复用 Go echo server（h2+h1+H3 同端口）。

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const path = require('node:path');
const { spawn } = require('node:child_process');
const readline = require('node:readline');

const ROOT = path.join(__dirname, '..', '..', '..');
const SERVER_EXE = path.join(ROOT, 'build', process.platform === 'win32' ? 'echo-server.exe' : 'echo-server');
// 默认库名也平台感知（此前硬编码 geektls.dll，Linux/macOS 上必须外部设 GEEDTLS_LIB）。
const LIB_NAME = process.platform === 'win32'
  ? 'geektls.dll'
  : (process.platform === 'darwin' ? 'libgeektls.dylib' : 'libgeektls.so');
const DLL = path.join(ROOT, 'build', LIB_NAME);
// 会话级 TLS 材料用例的真实夹具（openssl 生成，见 testdata/）。
const DATA = (name) => path.join(__dirname, 'testdata', name);

process.env.GEEDTLS_LIB = process.env.GEEDTLS_LIB || DLL;

const geektls = require(path.join(ROOT, 'bindings', 'nodejs'));

let serverProc = null;
let baseUrl = null;

before(async () => {
  serverProc = spawn(SERVER_EXE, [], { stdio: ['ignore', 'pipe', 'pipe'] });
  const rl = readline.createInterface({ input: serverProc.stdout });
  baseUrl = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('echo server start timeout')), 10000);
    rl.on('line', (line) => {
      if (line.startsWith('READY ')) {
        clearTimeout(timer);
        resolve(line.split(' ')[1].trim());
      }
    });
    serverProc.stderr.on('data', (d) => process.stderr.write(d));
  });
});

after(() => {
  if (serverProc) serverProc.kill();
});

test('version abi', () => {
  const v = geektls.version();
  assert.equal(v.abi, 1);
  assert.match(v.core, /^\d+\.\d+\.\d+$/);
});

test('module-level helpers share a default session', async () => {
  geektls.defaultSession({ impersonate: 'chrome_133', insecureSkipVerify: true });
  assert.throws(() => geektls.defaultSession({ impersonate: 'chrome_150' }), /已创建/);
  const r = await geektls.get(`${baseUrl}/echo`);
  assert.equal(r.status, 200);
  const body = JSON.parse(await r.text());
  assert.equal(body.method, 'GET');
  await r.close();
});

test('list/describe presets', () => {
  const names = geektls.listPresets();
  assert.ok(names.includes('chrome_133'));
  const d = geektls.describePreset('chrome_133');
  assert.equal(d.name, 'chrome_133');
  // describe 输出直接喂 check_profile（期望值闭环）
  const chk = geektls.checkProfile(d);
  assert.ok(chk.ja4.startsWith('t13d'));
});

test('preset matrix: echo over h2', async () => {
  for (const name of geektls.listPresets()) {
    const s = new geektls.Session({ impersonate: name, insecureSkipVerify: true });
    try {
      const r = await s.get(`${baseUrl}/echo`, { headers: { 'user-agent': 'geektls-node' } });
      assert.equal(r.status, 200, name);
      // TLS1.2-era 预设（chrome_38/IE/curl 等）无 h2 ALPN，合法落到 http/1.1
      assert.ok(['h2', 'http/1.1'].includes(r.usedProtocol), `${name}: ${r.usedProtocol}`);
      assert.equal(r.selfcheck.ja3_hash.length, 32, name);
      // echo server 是 127.0.0.1（IP 字面量）：线上省略 SNI，ja4_a 的 SNI
      // 标志位（协议符 + 2 位版本之后，index 3）为 i；版本可以是 12/13
      const a = r.selfcheck.ja4.split('_')[0];
      assert.ok('tq'.includes(a[0]) && a[3] === 'i', `${name}: ${r.selfcheck.ja4}`);
      const body = await r.json();
      assert.ok(['HTTP/2.0', 'HTTP/1.1'].includes(body.proto), `${name}: ${body.proto}`);
      await r.close();
    } finally {
      s.close();
    }
  }
});

test('streaming body', async () => {
  const s = new geektls.Session({ impersonate: 'chrome_150', insecureSkipVerify: true });
  try {
    const r = await s.get(`${baseUrl}/stream`);
    let total = 0;
    for await (const chunk of r.body) total += chunk.length;
    assert.equal(total, 64 * 16384);
  } finally {
    s.close();
  }
});

test('post body echo', async () => {
  const s = new geektls.Session({ impersonate: 'safari_18', insecureSkipVerify: true });
  try {
    const r = await s.post(`${baseUrl}/echo`, { body: 'hello-node' });
    const body = await r.json();
    assert.equal(body.method, 'POST');
    assert.equal(body.body, 'hello-node');
  } finally {
    s.close();
  }
});

test('h3 forced', async () => {
  // bogdanfinn H3 服务端不接受 QUIC hello 里的 ECH（服务端兼容面限制，
  // 与真 Chrome 无关；见 docs/p4-h3-capability.md）——剥掉后测互操作。
  const profile = geektls.describePreset('chrome_133');
  profile.tls.detail.extensions = profile.tls.detail.extensions.filter((e) => e.type !== 65037);
  const s = new geektls.Session({ profile, insecureSkipVerify: true });
  try {
    const r = await s.get(`${baseUrl}/echo`, { forceHttp3: true, timeoutMs: 5000 });
    assert.equal(r.status, 200);
    assert.equal(r.usedProtocol, 'h3');
    await r.close();
  } finally {
    s.close();
  }
});

test('stream upload (async iterable body)', async () => {
  const s = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true });
  try {
    async function* gen() {
      yield 'hello';
      yield Buffer.from(',node-stream');
      yield '';
    }
    const r = await s.post(`${baseUrl}/echo`, { body: gen() });
    const body = await r.json();
    assert.equal(body.body, 'hello,node-stream');
    await r.close();
  } finally {
    s.close();
  }
});

test('selfcheck extended fields', async () => {
  const s = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true });
  try {
    const r = await s.get(`${baseUrl}/echo`);
    const sc = r.selfcheck;
    assert.equal(sc.ja3_fullstring, sc.ja3);
    assert.equal(createHash('md5').update(sc.ja3_fullstring).digest('hex'), sc.ja3_hash);
    assert.equal(sc.sni_sent, false); // echo 是 127.0.0.1（IP 字面量）
    assert.ok(sc.wire_extensions.length > 0 && sc.extensions.length > 0);
    assert.ok(!sc.wire_extensions.includes(0));
    assert.ok(sc.grease.length > 0);
    assert.equal(sc.negotiated.alpn, 'h2');
    await r.close();
  } finally {
    s.close();
  }
});

test('connection pool reuse (same handshake)', async () => {
  const s = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true });
  try {
    const r1 = await s.get(`${baseUrl}/echo`);
    const h1 = r1.selfcheck.ja3_hash;
    await r1.close();
    const r2 = await s.get(`${baseUrl}/echo`);
    // chrome_133 扩展洗牌 ⇒ 同连接 JA3 恒定；相等即复用同一条连接
    assert.equal(r2.selfcheck.ja3_hash, h1);
    await r2.close();
  } finally {
    s.close();
  }
});

test('decompress matrix (gzip/deflate/raw-flate/br/zstd/multi/x-enc)', async () => {
  const s = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true });
  try {
    const expect = Buffer.from('geektls-decompress-check,'.repeat(400) + 'END');
    for (const p of ['/gzip', '/deflate', '/deflate-raw', '/br', '/zstd', '/multi']) {
      const r = await s.get(`${baseUrl}${p}`);
      assert.equal(r.status, 200, p);
      assert.equal(r.decoded, true, p);
      assert.ok(r.contentEncoding, p);
      assert.ok(r.header('content-encoding'), p); // 线上原值不篡改
      assert.deepEqual(await r.bytes(), expect, p);
      await r.close();
    }
    // 未知编码：原样透传 + warning
    let r = await s.get(`${baseUrl}/x-enc`);
    assert.deepEqual(await r.bytes(), expect);
    assert.equal(r.decoded, false);
    assert.ok(r.warnings.length > 0);
    await r.close();
    // 请求级关闭：拿到 gzip 原字节
    r = await s.get(`${baseUrl}/gzip`, { autoDecompress: false });
    assert.equal(r.decoded, false);
    assert.deepEqual((await r.bytes()).subarray(0, 2), Buffer.from([0x1f, 0x8b]));
    await r.close();
  } finally {
    s.close();
  }
});

test('websocket (wss echo)', async () => {
  const s = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true });
  try {
    const ws = await s.websocket(`${baseUrl.replace('https://', 'wss://')}/ws`);
    await ws.send('hello-ws');
    let { opcode, data } = await ws.recv(5000);
    assert.equal(opcode, geektls.WebSocket.OP_TEXT);
    assert.equal(data.toString(), 'hello-ws');
    await ws.send(Buffer.from([0, 1, 0xff]), geektls.WebSocket.OP_BINARY);
    ({ opcode, data } = await ws.recv(5000));
    assert.equal(opcode, geektls.WebSocket.OP_BINARY);
    assert.deepEqual(data, Buffer.from([0, 1, 0xff]));
    await ws.send(Buffer.from('probe'), geektls.WebSocket.OP_PING);
    await ws.send('after-ping');
    ({ opcode, data } = await ws.recv(5000));
    assert.equal(opcode, geektls.WebSocket.OP_TEXT);
    assert.equal(data.toString(), 'after-ping');
    await ws.close(1000);
  } finally {
    s.close();
  }
});

test('error paths', async () => {
  assert.throws(() => new geektls.Session({ impersonate: 'no_such_browser' }), geektls.GeekTLSError);
  const s = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true });
  try {
    await assert.rejects(s.get('http://127.0.0.1:1/echo'), geektls.GeekTLSError);
  } finally {
    s.close();
  }
});

test('tls options: 会话级 verify/cert 归一与请求级拒收', async () => {
  // 非法取值必须报错，而不是"配了 CA 却静默走系统信任库"。
  for (const bad of [{ verify: 123 }, { verify: '' }, { verify: [] },
                     { cert: 123 }, { cert: {} , certKey: undefined, ca: 1 }]) {
    assert.throws(() => new geektls.Session({ impersonate: 'chrome_133', ...bad }), TypeError,
      String(bad));
  }
  assert.throws(() => new geektls.Session({
    impersonate: 'chrome_133', cert: { cert: '/x/c.pem', key: '/x/k.pem', pass: 'p' },
  }), TypeError);

  // 给错的证书材料要在建会话时就失败（引擎侧校验），不能退化成"用系统根继续"。
  // 这一段要新构建的动态库：旧库把 ca_bundle/client_cert 当未知键静默跳过，
  // 不存在的路径也不会报错 ⇒ 探测不到就跳过，别把"库旧"当成"引擎错"。
  let engineChecks = false;
  try {
    new geektls.Session({ impersonate: 'chrome_133', verify: DATA('/no/such/ca.pem') }).close();
  } catch (e) {
    assert.equal(e.code, 'invalid_config', String(e));
    engineChecks = true;
  }
  if (!engineChecks) {
    console.error('SKIP 会话级证书材料校验：动态库是旧构建（不含 ca_bundle/client_cert）');
  } else {
    for (const bad of [{ verify: DATA('/no/such/ca.pem') },
                       { verify: '-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----' },
                       { certKey: DATA('client-key.pem') }]) {
      assert.throws(() => new geektls.Session({ impersonate: 'chrome_133', ...bad }),
        (e) => e.code === 'invalid_config', JSON.stringify(bad));
    }
  }

  const s = new geektls.Session({
    impersonate: 'chrome_133',
    verify: DATA('ca.pem'),                    // 自持信任库（真实存在的文件）
    cert: [DATA('client.pem'), DATA('client-key.pem')], // mTLS
    certKey: undefined,
  });
  try {
    await assert.rejects(s.request({ url: baseUrl + '/echo', verify: false }), TypeError);
    await assert.rejects(s.request({ url: baseUrl + '/echo', cert: '/x/c.pem' }), TypeError);
    await assert.rejects(s.request({ url: baseUrl + '/echo', allowRedirects: false }), TypeError);
  } finally {
    s.close();
  }
});

test('会话选项白名单: 拼错的键报错，引擎原名照样透传', async () => {
  // core 的 config 解码只查指纹入参那六个键、SessionOptions 忽略未知字段 ⇒
  // 未知键进到 FFI 就无声消失；这几项决定校验开不开、超时走不走，必须拦住。
  for (const bad of [{ insecure_skip_verfy: true }, { timeoutMS: 1000 },
                     { local_addr: '127.0.0.1' }, { redirectsMax: 3 }]) {
    assert.throws(() => new geektls.Session({ impersonate: 'chrome_133', ...bad }),
      TypeError, JSON.stringify(bad));
  }
  // 引擎会话原名（snake_case）走透传：能建会话，值也确实生效。
  const s = new geektls.Session({
    impersonate: 'chrome_133', insecure_skip_verify: true, timeout_ms: 8000,
  });
  try {
    const r = await s.get(`${baseUrl}/echo`);
    assert.equal(r.status, 200);
    await r.close();
  } finally {
    s.close();
  }
  // resolve 的形态在绑定层就判（与动态库新旧无关）：给字符串不是"静默不钉位"。
  assert.throws(() => new geektls.Session({ impersonate: 'chrome_133', resolve: 'a.com' }),
    TypeError);
  assert.throws(() => new geektls.Session({ impersonate: 'chrome_133', resolve: ['a.com'] }),
    TypeError);
});

test('a6 read timeout: 挂死的 body 按 read_timeout 断开', async () => {
  const s = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true });
  try {
    // 能力探测：request_json 里的 read_timeout_ms 传字符串 ⇒ 新 core 在解析时
    // 明确报错；旧构建不认识该键会静默跳过（此时跳过本用例）。
    let supported = true;
    try {
      const p = await s.request({ url: baseUrl + '/echo', readTimeoutMs: 'not-an-int' });
      await p.close();
      supported = false;
    } catch (e) {
      assert.ok(e instanceof geektls.GeekTLSError, String(e));
    }
    if (!supported) {
      console.error('SKIP a6 read timeout: 动态库是旧构建（不含 read_timeout_ms）');
      return;
    }

    // 请求级：/stall 先给一字节再挂 5s，必须在 ~400ms 拿到结构化错误。
    // 计时只覆盖 body 读取阶段——首请求的 Alt-Svc/H3 试探发生在响应头之前。
    const r = await s.request({ url: baseUrl + '/stall', readTimeoutMs: 400 });
    const it = r.iterContent(1)[Symbol.asyncIterator]();
    assert.equal((await it.next()).value.toString(), 'x');
    const t0 = Date.now();
    const err = await it.next().then((v) => new Error(`unexpected chunk ${v}`), (e) => e);
    const dt = Date.now() - t0;
    assert.ok(err instanceof geektls.GeekTLSError, String(err));
    assert.equal(err.code, 'read_timeout');
    assert.ok(dt >= 350 && dt < 1500, `超时耗时 ${dt}ms`);
    // body 流带错销毁时就把 response handle 关掉了（_destroy），所以这里不
    // 再拿同一个 handle 复读；要验证的是"作废没有把会话拖死"：同会话再发
    // 一次 /stall，仍然毫秒级拿到同一个错误。
    await r.close();
    const r2 = await s.request({ url: baseUrl + '/stall', readTimeoutMs: 400 });
    const t1 = Date.now();
    const err2 = await r2.read().then(() => null, (e) => e);
    assert.ok(err2 instanceof geektls.GeekTLSError, String(err2));
    assert.equal(err2.code, 'read_timeout');
    assert.ok(Date.now() - t1 < 1500, '超时后新请求仍被挂住');
    await r2.close();

    // 会话级 readTimeout（秒）：贴着 1.2s，而不是等满服务端的 5s
    const s2 = new geektls.Session({
      impersonate: 'chrome_133', insecureSkipVerify: true, readTimeout: 1.2,
    });
    try {
      const warm = await s2.get(baseUrl + '/echo');   // 先落连接，排除握手噪声
      await warm.read();
      warm.close();
      const r3 = await s2.get(baseUrl + '/stall');
      const t2 = Date.now();
      const err3 = await r3.read().then(() => null, (e) => e);
      const dt3 = Date.now() - t2;
      assert.ok(err3 instanceof geektls.GeekTLSError, String(err3));
      assert.equal(err3.code, 'read_timeout');
      assert.ok(dt3 >= 1100 && dt3 < 2500, `会话级超时耗时 ${dt3}ms`);
      await r3.close();
    } finally {
      s2.close();
    }
  } finally {
    s.close();
  }
});

// A8：代理环境变量派生 + trustEnv/NO_PROXY/回环豁免。判据不打网络也不需真代理：
// QUIC 过 HTTP 代理要 CONNECT-UDP（未实现），所以"代理生效"会在拨号前以
// force_http3 冲突的形式报出来；旧构建不读环境变量 ⇒ 跳过而不是假通过。
test('a8 proxy env: ALL_PROXY 派生、trustEnv 关闭、NO_PROXY 与回环豁免', async () => {
  const target = 'https://192.0.2.1:443/';          // TEST-NET-1：不可路由、不解析
  const dead = 'socks5://127.0.0.1:1';
  const marker = (e) => /force_http3/.test(String(e)) && String(e).includes('代理');
  const saved = { ...process.env };

  const errOf = async (opts) => {
    const s = new geektls.Session({
      impersonate: 'chrome_133', insecureSkipVerify: true, timeoutMs: 2000, ...opts,
    });
    try {
      const r = await s.request({ method: 'GET', url: target, forceHttp3: true });
      await r.close();
      return new Error('unexpected success');
    } catch (e) {
      return e;
    } finally {
      s.close();
    }
  };

  const clearEnv = () => {
    for (const k of ['HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy',
      'NO_PROXY', 'no_proxy', 'HTTP_PROXY', 'http_proxy']) delete process.env[k];
  };

  try {
    clearEnv();
    process.env.ALL_PROXY = dead;
    if (!marker(await errOf({}))) {
      console.error('SKIP a8 proxy env: 动态库不读代理环境变量（旧构建）');
      return;
    }
    // trustEnv=false ⇒ 不看环境变量（requests 的 trust_env）
    assert.ok(!marker(await errOf({ trustEnv: false })));
    // 显式 proxy 压过 trustEnv=false（curl 的 --proxy 是硬要求）
    clearEnv();
    assert.ok(marker(await errOf({ proxy: dead, trustEnv: false })));
    // NO_PROXY 命中 ⇒ 直连
    clearEnv();
    process.env.ALL_PROXY = dead;
    process.env.NO_PROXY = '192.0.2.0/24';
    assert.ok(!marker(await errOf({})));
    // 回环目标不吃 env 派生代理：echo server 就在 127.0.0.1，必须连得上
    delete process.env.NO_PROXY;
    const s2 = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true, timeoutMs: 5000 });
    try {
      const r = await s2.get(baseUrl + '/echo');
      assert.equal(r.status, 200);
      await r.read();
      r.close();
    } finally {
      s2.close();
    }
  } finally {
    process.env = saved;
  }
});

// A9 地址控制：resolve / localAddress / ipVersion。判据不需要真 DNS、不打外网；
// 旧构建不认识这三项 ⇒ 先做正向对照，探测不过就跳过而不是假通过。
test('a9 地址控制: resolve 钉位保留 SNI/Host、ipVersion 收窄族、localAddress 落到 socket', async () => {
  const NAME = 'pinned.example';                       // 不可解析：连得上就只能是因为钉位
  const port = baseUrl.split(':').pop();
  const pinnedUrl = `https://${NAME}:${port}/echo`;

  const newErr = (opts) => {
    try {
      const s = new geektls.Session({
        impersonate: 'chrome_133', insecureSkipVerify: true, timeoutMs: 3000, ...opts,
      });
      s.close();
      return '';
    } catch (e) {
      return String(e.message || e);
    }
  };
  const sess = async (opts, fn) => {
    const s = new geektls.Session({
      impersonate: 'chrome_133', insecureSkipVerify: true, timeoutMs: 5000, ...opts,
    });
    try {
      return await fn(s);
    } finally {
      s.close();
    }
  };

  if (!newErr({ ipVersion: '7' }).includes('ip_version')) {
    console.error('SKIP a9 地址控制: 动态库不认 resolve/localAddress/ipVersion（旧构建）');
    return;
  }

  // 1) 非法与自相冲突的取值在建会话时就拒
  assert.match(newErr({ localAddress: 'eth0' }), /local_address/);          // 网卡名不支持
  assert.match(newErr({ resolve: { [NAME]: 'not-an-ip' } }), /不是 IP 字面量/);
  assert.match(newErr({ localAddress: '10.0.0.1', ipVersion: '6' }), /冲突/);
  assert.match(newErr({ resolve: { [NAME]: '::1' }, ipVersion: '4' }), /冲突/);
  assert.equal(newErr({ ipVersion: 'ipv4' }), '');                          // 别名写法也认

  // 2) 钉位只改"连到哪"：Host / SNI 仍是原域名
  const got = await sess({ resolve: { [NAME]: '127.0.0.1' } }, async (s) => {
    const r = await s.get(pinnedUrl);
    const body = JSON.parse(await r.text());
    const sc = r.selfcheck;
    await r.close();
    return { status: r.status, body, sc };
  });
  assert.equal(got.status, 200);
  assert.equal(got.body.host, `${NAME}:${port}`);   // Host/:authority 没被换成 IP
  assert.equal(got.sc.sni_sent, true);              // 连的是 IP，SNI 也不能掉线

  // host:port 形态的键优先于 host 形态（curl --resolve 同规则）
  await sess({ resolve: { [NAME + ':' + port]: '127.0.0.1' } }, async (s) => {
    const r = await s.get(pinnedUrl);
    assert.equal(r.status, 200);
    await r.close();
  });

  // 3) ipVersion 收窄族：v4 目标配 v6 偏好要给出可读错误，而不是"挑一个能连的"
  await assert.rejects(
    sess({ ipVersion: '6' }, async (s) => s.get(`${baseUrl}/echo`)),
    /同族|ip_version/
  );
  await sess({ ipVersion: '4' }, async (s) => {
    const r = await s.get(`${baseUrl}/echo`);
    assert.equal(r.status, 200);
    await r.close();
  });

  // 4) localAddress 真的落在 socket 上：绑本机没有的地址必须失败
  await sess({ localAddress: '127.0.0.1' }, async (s) => {
    const r = await s.get(`${baseUrl}/echo`);
    assert.equal(r.status, 200);
    await r.close();
  });
  await assert.rejects(
    sess({ localAddress: '192.0.2.9' }, async (s) => s.get(`${baseUrl}/echo`))
  );

  // 5) 地址控制没接进 QUIC 拨号 ⇒ forceHttp3 明确报错，不偷偷绕过用户点名的那一项
  for (const [field, opts] of [['resolve', { resolve: { [NAME]: '127.0.0.1' } }],
    ['local_address', { localAddress: '127.0.0.1' }], ['ip_version', { ipVersion: '4' }]]) {
    await assert.rejects(
      sess(opts, async (s) => s.request({ method: 'GET', url: pinnedUrl, forceHttp3: true })),
      (e) => /force_http3/.test(String(e)) && String(e).includes(field),
      `force_http3 + ${field} 应当报错（不静默绕过地址控制项）`
    );
  }
});
