"""import_pcap 绑定用例（v0.2.0）：测试内合成 pcap 字节，零外部依赖。

覆盖：path/data 双入口、乱序重组、tcp 节、resumption 拒绝、all_streams、
clienthello_hex → Session 装载（构造成功即装载链路通）。
"""

import struct

import pytest

from test_requests_parity import _ensure_lib

_ensure_lib()
import geektls  # noqa: E402

SYN, SYN_ACK, ACK, PSH_ACK = 0x02, 0x12, 0x10, 0x18
SYN_OPTS = b"\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02"
SRC = bytes([192, 168, 1, 10])
DST = bytes([93, 184, 216, 34])


def _frame(src, dst, seg):
    ip_total = 20 + len(seg)
    # ver/ihl, tos, total, id, flags_frag(DF=1), ttl, proto, csum=0（核不校验）
    ip = bytearray(struct.pack(">BBHHHBBH", 0x45, 0, ip_total, 0, 0x4000, 64, 6, 0) + src + dst)
    return b"\x00" * 12 + b"\x08\x00" + bytes(ip) + seg


def _tcp_seg(sport, dport, seq, ack, flags, win, opts, payload):
    doff = (20 + len(opts)) // 4
    return (
        struct.pack(">HHIIBBHHH", sport, dport, seq, ack, doff << 4, flags, win, 0, 0)
        + opts
        + payload
    )


def _cli_frame(sport, seq, flags, opts=b"", payload=b""):
    ack = 0 if (flags & SYN) and not (flags & 0x10) else 5001
    return _frame(SRC, DST, _tcp_seg(sport, 443, seq, ack, flags, 64240, opts, payload))


def _srv_frame(sport):
    return _frame(DST, SRC, _tcp_seg(443, sport, 5000, 1001, SYN_ACK, 65535, b"", b""))


def build_ch(psk=False, seed=0xAB):
    """最小合法 ClientHello record（16 03 01 开头）。"""
    body = b"\x03\x03" + bytes([seed]) * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    ext = (
        b"\x00\x29\x00\x05\x00\x03\x01\x02\x03"
        if psk
        else b"\x00\x2b\x00\x02\x03\x04"
    )
    body += len(ext).to_bytes(2, "big") + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


# --- PART2 ---


def session_frames(ch, sport):
    """SYN(带选项) + SYN-ACK + ACK + CH 分 3 段乱序。"""
    a, b = len(ch) // 3, len(ch) * 2 // 3
    return [
        _cli_frame(sport, 1000, SYN, opts=SYN_OPTS),
        _srv_frame(sport),
        _cli_frame(sport, 1001, ACK),
        _cli_frame(sport, 1001 + 2 * a, PSH_ACK, payload=ch[2 * a :]),
        _cli_frame(sport, 1001 + a, PSH_ACK, payload=ch[a : 2 * a]),
        _cli_frame(sport, 1001, PSH_ACK, payload=ch[:a]),
    ]


def write_pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 0, len(f), len(f)) + f
    return out


def test_import_pcap_path(tmp_path):
    ch = build_ch()
    p = tmp_path / "cap.pcap"
    p.write_bytes(write_pcap(session_frames(ch, 51423)))
    res = geektls.import_pcap(str(p), source_base="cap")
    assert res["skipped"] == []
    rec = res["records"][0]
    assert rec["kind"] == "e1p_pcap" and rec["grade"] == "E1p"
    assert bytes.fromhex(rec["clienthello_hex"]) == ch
    assert rec["ja3"] and rec["ja4"]
    assert rec["tcp"]["mss"] == 1460 and rec["tcp"]["window_scale"] == 8
    assert rec["tcp"]["ttl"] == 64 and rec["tcp"]["df"] is True
    assert ",".join(rec["tcp"]["options_order"]) == "mss,nop,ws,nop,nop,sack"
    assert rec["name"] == "cap" and rec["source"] == "pcap:cap#1"


# --- PART3 ---


def test_import_pcap_data_b64_and_all(tmp_path):
    ch1, ch2 = build_ch(seed=0xAB), build_ch(seed=0xCD)
    frames = session_frames(ch1, 51001) + session_frames(ch2, 51002)
    data = write_pcap(frames)

    res = geektls.import_pcap(data=data, all_streams=True)
    assert len(res["records"]) == 2
    assert bytes.fromhex(res["records"][1]["clienthello_hex"]) == ch2

    one = geektls.import_pcap(data=data, stream=2)
    assert bytes.fromhex(one["records"][0]["clienthello_hex"]) == ch2

    with pytest.raises(ValueError):
        geektls.import_pcap()


def test_import_pcap_rejects(tmp_path):
    res = geektls.import_pcap(data=write_pcap(session_frames(build_ch(psk=True), 51423)))
    assert res["records"] == []
    assert "resumption" in res["skipped"][0]


def test_import_pcap_loads_session(tmp_path):
    """端到端：pcap → clienthello_hex → Session 装载（构造成功即链路通）。"""
    p = tmp_path / "cap.pcap"
    p.write_bytes(write_pcap(session_frames(build_ch(), 51423)))
    rec = geektls.import_pcap(str(p))["records"][0]
    with geektls.Session(clienthello_hex=rec["clienthello_hex"]) as s:
        assert s is not None
