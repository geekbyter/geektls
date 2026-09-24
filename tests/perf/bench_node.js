'use strict';

// P7-T4 性能基准（Node FFI 链路）。用法：node tests/perf/bench_node.js

const path = require('node:path');
const { spawn } = require('node:child_process');
const readline = require('node:readline');

const ROOT = path.join(__dirname, '..', '..');
process.env.GEEDTLS_LIB = process.env.GEEDTLS_LIB || path.join(ROOT, 'build', 'geektls.dll');
const geektls = require(path.join(ROOT, 'bindings', 'nodejs'));

function startEcho() {
  return new Promise((resolve, reject) => {
    const proc = spawn(path.join(ROOT, 'build', 'echo-server.exe'), [], { stdio: ['ignore', 'pipe', 'pipe'] });
    const rl = readline.createInterface({ input: proc.stdout });
    const timer = setTimeout(() => reject(new Error('echo timeout')), 10000);
    rl.on('line', (line) => {
      if (line.startsWith('READY ')) {
        clearTimeout(timer);
        resolve({ proc, base: line.split(' ')[1].trim() });
      }
    });
  });
}

// 基准说明：本机 echo 用 bogdanfinn H3 服务端（拒 ECH），完整预设会触发
// 每会话一次 3s H3 失败回退（libuv 4 线程池在高并发下雪崩）——用剥 ECH
// 变体测稳态请求路径；预热行为差异记入 docs/benchmarks.md。
const profile = geektls.describePreset('chrome_133');
profile.tls.detail.extensions = profile.tls.detail.extensions.filter((e) => e.type !== 65037);

async function throughput(base, concurrency, durMs = 10000) {
  const stopAt = Date.now() + durMs;
  let total = 0;
  let errors = 0;
  async function worker() {
    const s = new geektls.Session({ profile, insecureSkipVerify: true });
    try {
      while (Date.now() < stopAt) {
        try {
          const r = await s.get(`${base}/echo`);
          await r.close();
          total++;
        } catch {
          errors++;
        }
      }
    } finally {
      s.close();
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  return { total, errors };
}

(async () => {
  const { proc, base } = await startEcho();
  try {
    for (const c of [10, 50, 100]) {
      const { total, errors } = await throughput(base, c);
      console.log(`node-ffi  concurrency=${String(c).padStart(3)}: ${total} reqs in 10s = ${(total / 10).toFixed(0)} req/s (errors: ${errors})`);
    }
  } finally {
    proc.kill();
  }
})();
