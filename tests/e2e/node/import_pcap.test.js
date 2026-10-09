"use strict";
// importPcap tests (v0.2.0): synthetic pcap bytes, no external deps.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const ROOT = path.join(__dirname, "..", "..", "..");
const LIB = process.platform === "win32" ? "geektls.dll" : (process.platform === "darwin" ? "libgeektls.dylib" : "libgeektls.so");
process.env.GEEDTLS_LIB = process.env.GEEDTLS_LIB || path.join(ROOT, "build", LIB);
const geektls = require(path.join(ROOT, "bindings", "nodejs"));
const SYN = 0x02, SYN_ACK = 0x12, ACK = 0x10, PSH_ACK = 0x18;
const SYN_OPTS = Buffer.from([2, 4, 5, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2]);
const SRC = Buffer.from([192, 168, 1, 10]);
const DST = Buffer.from([93, 184, 216, 34]);

function frame(src, dst, sport, dport, seq, ack, flags, opts, payload) {
  const doff = (20 + opts.length) / 4;
  const tcp = Buffer.alloc(20 + opts.length + payload.length);
  tcp.writeUInt16BE(sport, 0); tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq, 4); tcp.writeUInt32BE(ack, 8);
  tcp[12] = doff << 4; tcp[13] = flags; tcp.writeUInt16BE(64240, 14);
  opts.copy(tcp, 20); payload.copy(tcp, 20 + opts.length);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45; ip.writeUInt16BE(20 + tcp.length, 2);
  ip.writeUInt16BE(0x4000, 6); ip[8] = 64; ip[9] = 6;
  src.copy(ip, 12); dst.copy(ip, 16);
  const eth = Buffer.alloc(14); eth[12] = 0x08; eth[13] = 0x00;
  return Buffer.concat([eth, ip, tcp]);
}
const cliFrame = (sport, seq, flags, opts, payload) => frame(SRC, DST, sport, 443, seq, (flags & SYN) && !(flags & 0x10) ? 0 : 5001, flags, opts || Buffer.alloc(0), payload || Buffer.alloc(0));
const srvFrame = (sport) => frame(DST, SRC, 443, sport, 5000, 1001, SYN_ACK, Buffer.alloc(0), Buffer.alloc(0));
function buildCH(psk, seed) {
  seed = seed === undefined ? 0xAB : seed;
  let body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32, seed), Buffer.from([0, 0, 2, 0x13, 0x01, 1, 0])]);
  const ext = psk ? Buffer.from([0, 0x29, 0, 5, 0, 3, 1, 2, 3]) : Buffer.from([0, 0x2b, 0, 2, 3, 4]);
  const len = Buffer.alloc(2); len.writeUInt16BE(ext.length);
  body = Buffer.concat([body, len, ext]);
  const hsLen = Buffer.alloc(4); hsLen[0] = 1; hsLen.writeUIntBE(body.length, 1, 3);
  const rec = Buffer.alloc(5); rec[0] = 0x16; rec[1] = 3; rec[2] = 1; rec.writeUInt16BE(4 + body.length, 3);
  return Buffer.concat([rec, hsLen, body]);
}

function sessionFrames(ch, sport) {
  const a = Math.floor(ch.length / 3), b = Math.floor(ch.length * 2 / 3);
  return [
    cliFrame(sport, 1000, SYN, SYN_OPTS, Buffer.alloc(0)),
    srvFrame(sport),
    cliFrame(sport, 1001, ACK, Buffer.alloc(0), Buffer.alloc(0)),
    cliFrame(sport, 1001 + 2 * a, PSH_ACK, Buffer.alloc(0), ch.slice(2 * a)),
    cliFrame(sport, 1001 + a, PSH_ACK, Buffer.alloc(0), ch.slice(a, 2 * a)),
    cliFrame(sport, 1001, PSH_ACK, Buffer.alloc(0), ch.slice(0, a)),
  ];
}
function writePcap(frames) {
  const head = Buffer.alloc(24);
  head.writeUInt32LE(0xa1b2c3d4, 0); head.writeUInt32LE(2, 4);
  head.writeUInt32LE(4, 8); head.writeUInt32LE(1, 20);
  const parts = [head];
  frames.forEach((f, i) => {
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(1700000000 + i, 0); rec.writeUInt32LE(f.length, 8); rec.writeUInt32LE(f.length, 12);
    parts.push(rec, f);
  });
  return Buffer.concat(parts);
}

test("importPcap path + data + all", () => {
  const ch1 = buildCH(false), ch2 = buildCH(false, 0xCD);
  const data = writePcap([...sessionFrames(ch1, 51001), ...sessionFrames(ch2, 51002)]);
  const res = geektls.importPcap({ data, all: true }); console.error("DBG", JSON.stringify(res).slice(0, 500));
  assert.equal(res.records.length, 2);
  assert.equal(res.records[0].kind, "e1p_pcap");
  assert.ok(res.records[0].clienthello_hex.length > 100);
  assert.ok(res.records[0].ja3 && res.records[0].ja4);
  assert.equal(res.records[0].tcp.mss, 1460);
  assert.equal(res.records[0].tcp.window_scale, 8);
  assert.equal(res.records[0].tcp.options_order.join(","), "mss,nop,ws,nop,nop,sack");
  const one = geektls.importPcap({ data, stream: 2 });
  assert.equal(Buffer.from(one.records[0].clienthello_hex, "hex")[11], 0xCD);
});

test("importPcap rejects resumption", () => {
  const res = geektls.importPcap({ data: writePcap(sessionFrames(buildCH(true), 51423)) });
  assert.equal(res.records.length, 0);
  assert.match(res.skipped[0], /resumption/);
});

test("importPcap - loads", () => {
  const res = geektls.importPcap({ data: writePcap(sessionFrames(buildCH(false), 51423)) });
  const rec = res.records[0];
  const s = new geektls.Session({ clienthello_hex: rec.clienthello_hex });
  assert.ok(s);
  s.close();
});
