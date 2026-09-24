'use strict';

// P0 冒烟：加载 c-shared 动态库，调 gtls_version，校验 abi==1。
// 库搜索顺序见 bindings/nodejs/index.js（GEEDTLS_LIB 环境变量优先）。

const path = require('node:path');
const geektls = require(path.join(__dirname, '..', '..', 'bindings', 'nodejs'));

const v = geektls.version();
console.log('geektls version:', JSON.stringify(v));
if (v.abi !== 1) {
  console.error(`abi mismatch: ${JSON.stringify(v)}`);
  process.exit(1);
}
console.log('node smoke OK');
