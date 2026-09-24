'use strict';

// 跨语言一致性用：对 echo 发一个请求，stdout 打印 selfcheck JSON。
// 用法：selfcheck.js <preset> <base_url>

const path = require('node:path');
const ROOT = path.join(__dirname, '..', '..', '..');
const geektls = require(path.join(ROOT, 'bindings', 'nodejs'));

(async () => {
  const [preset, base] = [process.argv[2], process.argv[3]];
  const s = new geektls.Session({ impersonate: preset, insecureSkipVerify: true });
  try {
    const r = await s.get(`${base}/echo`);
    console.log(JSON.stringify({
      ja3_hash: r.selfcheck.ja3_hash || '',
      ja4: r.selfcheck.ja4 || '',
      proto: r.usedProtocol,
    }));
    await r.close();
  } finally {
    s.close();
  }
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
