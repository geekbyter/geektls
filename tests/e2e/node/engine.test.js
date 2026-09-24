'use strict';

// P5 Node 绑定用例（node:test）：复用 Go echo server（h2+h1+H3 同端口）。

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');
const readline = require('node:readline');

const ROOT = path.join(__dirname, '..', '..', '..');
const SERVER_EXE = path.join(ROOT, 'build', process.platform === 'win32' ? 'echo-server.exe' : 'echo-server');
const DLL = path.join(ROOT, 'build', 'geektls.dll');

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
  assert.equal(v.core, '0.1.0');
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
      assert.equal(r.usedProtocol, 'h2', name);
      assert.equal(r.selfcheck.ja3_hash.length, 32, name);
      assert.ok(r.selfcheck.ja4.startsWith('t13d'), `${name}: ${r.selfcheck.ja4}`);
      const body = await r.json();
      assert.equal(body.proto, 'HTTP/2.0', name);
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

test('error paths', async () => {
  assert.throws(() => new geektls.Session({ impersonate: 'no_such_browser' }), geektls.GeekTLSError);
  const s = new geektls.Session({ impersonate: 'chrome_133', insecureSkipVerify: true });
  try {
    await assert.rejects(s.get('http://127.0.0.1:1/echo'), geektls.GeekTLSError);
  } finally {
    s.close();
  }
});
