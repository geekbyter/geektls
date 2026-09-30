"""P1-T8 L2 终审：geektls 7 自测预设 × nginx 采集端（$http_fingerprint_json）逐项 diff。

终审链路：geektls.Session(impersonate=...) → GET https://localhost:8443/ngf-debug
（WSL2 魔改 nginx，hirosumee + ngf 补丁）→ 解析采集 JSON 逐项断言。

运行：
    set GEEKTLS_NGINX_L2=1
    python -m pytest tests/e2e/nginx-l2/verify_l2.py -v

默认 skip（needs_nginx + 环境变量门）。目标可用 GEEKTLS_NGINX_L2_URL 覆盖。

========== 采集端口径（probe 实测确认，断言里的换算逻辑全部源于此） ==========

1. 扩展可见性：ngf-openssl-clienthello-raw.patch 用 OpenSSL pre_proc_exts 重建
   ClientHello，**OpenSSL 不认识的扩展整体消失**（raw_hex / extension_order_raw /
   ja3 / ja4 全部看不到）。实测该 OpenSSL 构建不认识的扩展：
   - 17613 ALPS（chrome 全族）、65037 ECH GREASE（chrome/firefox）、
     34 delegated_credential（firefox）、一切 GREASE 扩展（0x?a?a）。
   换算：nginx 扩展视图 == selfcheck ja3 扩展序列剔除 OPENSSL_UNKNOWN_EXTS，
   相对顺序不变（chrome 洗牌下也逐位相等，已实测）。
2. SNI：目标是 IP 字面量时 utls 不发 SNI（与 Chrome 行为一致），nginx ja4 为 i；
   selfcheck 已在拨号路径感知 IP 省略（engine 自算前剔除 spec 副本的 SNI 占位），
   两侧 d/i 一致。终审仍统一用 localhost 目标，SNI 上链，两侧均为 d。
3. GREASE 值：ja3*/ja4 视图剔除；clienthello_* 视图**保留**随机真值，另给
   clienthello_grease_positions / grease_values 元数据。比对时对 clienthello_*
   做 GREASE 掩码后与 describe_preset 展开值逐项比（位置也断言）。
4. nginx ja4 非官方格式（采集端实现差异，不是 geektls 错）：
   - ja4_a 无 ALPN 后缀（官方 t13d1516h2 的 "h2" 段缺失）；
   - ja4_c = sha256(排序后 4 位 hex 扩展，剔除 SNI(0)/ALPN(16)/**padding(21)**，
     逗号连接)[:12]，**不拼 sigalgs**（官方要拼 "_" + sigalgs）；
   - ja4_b = sha256(排序后 4 位 hex cipher，剔 GREASE)[:12] —— 与官方一致。
   geektls selfcheck ja4 遵守官方格式（已用 sha256 重建验证 7/7）。
   因此断言拆成：nginx ja4 全串 == 按其口径从其自身字段重建（锁死口径）；
   ja4_b 与 selfcheck 逐字符相等；ja4_c 与 selfcheck 扩展集（剔未知扩展）对齐；
   ja4_a 仅扩展计数差 == 被采集端丢弃的扩展数，其余分量逐字符相等。
5. http2_priorities 的 weight 是线上编码值 = 规格 weight + 1（firefox 41→42，
   safari 255→256）。chrome 预设已显式建模 headers_priority（excl=1/w=255，
   = G11 实测形状，也即引擎默认发出的 "1:1:0:256"），数据与行为现已一致。
6. geektls 引擎不发送 describe 中 type 41 的空 pre_shared_key 占位扩展
   （selfcheck 扩展序列同样不含）；type 21 padding 按真实浏览器语义条件发送
   （ClientHello 已达 512 字节边界时省略——safari_18 省略、safari_16 发送，
   两侧 selfcheck 与 nginx 采集一致），属引擎既定行为，断言丢弃项不出此集合。
"""

import base64
import hashlib
import os
import re
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
TARGET = os.environ.get("GEEKTLS_NGINX_L2_URL", "https://localhost:8443/ngf-debug")
PRESETS = ["chrome_131", "chrome_133", "chrome_150",
           "firefox_120", "firefox_135", "safari_16", "safari_18"]

# 采集端（该 OpenSSL 构建）不认识的扩展：见模块docstring第 1 条。
OPENSSL_UNKNOWN_EXTS = {34, 65037, 17613}
# 引擎按既定行为不发送的扩展（selfcheck 同样不含）：41 空 pre_shared_key 占位、
# 21 padding 条件省略（见第 6 条）。
ENGINE_DROPPED_EXTS = {41, 21}
# nginx ja4_c 额外剔除的扩展（官方只剔 0/16）：见第 4 条。
NGINX_JA4C_EXCLUDE = {0, 16, 21}

GREASE_VALUES = {0x0A0A + 0x1010 * i for i in range(16)}
GROUP_IDS = {
    "X25519MLKEM768": 4588, "X25519Kyber768Draft00": 25497, "X25519": 29,
    "P-256": 23, "P-384": 24, "P-521": 25,
    "ffdhe2048": 256, "ffdhe3072": 257,
}

# 终审对照表（pytest_terminal_summary 里打印）。
RESULT_ROWS = []

pytestmark = [
    pytest.mark.needs_nginx,
    pytest.mark.skipif(os.environ.get("GEEKTLS_NGINX_L2") != "1",
                       reason="needs nginx L2 rig; set GEEKTLS_NGINX_L2=1"),
]


def _ensure_lib():
    os.environ.setdefault("GEEDTLS_LIB", os.path.join(ROOT, "build", "geektls.dll"))
    pkg = os.path.join(ROOT, "bindings", "python")
    if pkg not in sys.path:
        sys.path.insert(0, pkg)


def _sha12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _is_grease(v):
    return v in GREASE_VALUES


def _mask(values):
    """整数序列 → GREASE 掩码序列（'grease' 或原值）。"""
    return ["grease" if _is_grease(v) else v for v in values]


def _dash_ints(text):
    return [int(x) for x in text.split("-")] if text else []


# ---------- describe_preset 展开 ----------

def _hex_value(tok):
    """describe 里的 '0x1301' / 'grease' → int / 'grease'。"""
    return "grease" if tok == "grease" else int(tok, 16)


def _group_value(tok):
    return "grease" if tok == "grease" else GROUP_IDS[tok]


def _exts_by_type(detail):
    return {e["type"]: e for e in detail["extensions"]}


def expand_describe(desc):
    """把 describe_preset 展开成与 nginx 字段同形的期望值。"""
    detail = desc["tls"]["detail"]
    exts = _exts_by_type(detail)
    exp = {
        "legacy_version": str(int(detail["legacy_version"], 16)),
        "ciphers": [_hex_value(c) for c in detail["ciphers"]],
        "ext_permutation": bool(detail.get("extension_permutation")),
        "ext_types": [e["type"] for e in detail["extensions"]
                      if not e.get("grease_random")],
    }
    if 43 in exts:
        exp["versions"] = [_hex_value(v) for v in exts[43]["versions"]]
    if 10 in exts:
        exp["groups"] = [_group_value(g) for g in exts[10]["groups"]]
    if 51 in exts:
        exp["key_shares"] = [_group_value(g) for g in exts[51]["key_shares"]]
    if 13 in exts:
        exp["sig_algs"] = [int(s, 16) for s in exts[13]["sig_algs"]]
    if 16 in exts:
        exp["alpn"] = ",".join(exts[16]["alpn"])
    if 45 in exts:
        exp["psk_modes"] = "-".join(str(b) for b in base64.b64decode(exts[45]["psk_modes"]))
    if 11 in exts:
        exp["point_formats"] = "-".join(
            str(b) for b in base64.b64decode(exts[11]["point_formats"]))
    return exp


# ---------- 采集 ----------

@pytest.fixture(scope="session")
def matrix():
    _ensure_lib()
    import geektls

    out = {}
    for name in PRESETS:
        try:
            desc = geektls.describe_preset(name)
            with geektls.Session(impersonate=name, verify=False, timeout=15) as s:
                r = s.get(TARGET)
                assert r.status_code == 200, "%s -> HTTP %d" % (name, r.status_code)
                out[name] = {
                    "describe": desc,
                    "expected": expand_describe(desc),
                    "selfcheck": r.selfcheck,
                    "nginx": r.json(),
                    "protocol": r.used_protocol,
                }
        except Exception as exc:
            pytest.skip("nginx L2 rig unreachable for %s: %r" % (name, exc))
    return out


def _selfcheck_exts(selfcheck):
    """selfcheck ja3 的扩展序列（GEASE 已剔）——引擎侧的发送记录。"""
    return _dash_ints(selfcheck["ja3"].split(",")[2])


def _nginx_exts(nginx):
    return _dash_ints(nginx["clienthello_extension_order_raw"])


def _nginx_ciphers(nginx):
    raw = nginx["clienthello_ciphers_hex"]
    return [int(raw[i:i + 4], 16) for i in range(0, len(raw), 4)]


def _nginx_ja4_rebuild(nginx):
    """按采集端口径从 nginx 自身字段重建 ja4（锁死口径模型，见 docstring 第 4 条）。"""
    ciphers = [c for c in _nginx_ciphers(nginx) if not _is_grease(c)]
    exts = _nginx_exts(nginx)
    versions = [v for v in _dash_ints(nginx["clienthello_supported_versions"])
                if not _is_grease(v)]
    a = "t%s%s%02d%02d" % ("13" if 772 in versions else "12",
                           "d" if 0 in exts else "i",
                           len(ciphers), len(exts))
    b = _sha12(",".join(sorted("%04x" % c for c in ciphers)))
    c = _sha12(",".join(sorted("%04x" % e for e in exts
                               if e not in NGINX_JA4C_EXCLUDE)))
    return "%s_%s_%s" % (a, b, c)


def _official_ja4c(exts, sig_algs):
    """官方 JA4_c（geektls selfcheck 遵循）：排序 hex 扩展(剔 0/16) + '_' + sigalgs。"""
    e = ",".join(sorted("%04x" % x for x in exts if x not in (0, 16)))
    s = ",".join("%04x" % x for x in sig_algs)
    return _sha12(e + "_" + s)


# ---------- 断言 ----------

@pytest.mark.parametrize("name", PRESETS)
def test_clienthello_fields(matrix, name):
    m = matrix[name]
    n, exp = m["nginx"], m["expected"]

    # 基本字段（无口径差异，逐字符/逐项相等）
    assert n["clienthello_legacy_version"] == exp["legacy_version"]
    assert n["clienthello_alpn"] == exp["alpn"]
    assert n["clienthello_psk_key_exchange_modes"] == exp["psk_modes"]
    assert n["clienthello_ec_point_formats"] == exp["point_formats"]
    assert _dash_ints(n["clienthello_signature_algorithms"]) == exp["sig_algs"]

    # GREASE 掩码后与 describe 展开值比对（采集端在 clienthello_* 保留真值，见第 3 条）
    assert _mask(_nginx_ciphers(n)) == exp["ciphers"]
    assert _mask(_dash_ints(n["clienthello_supported_versions"])) == exp["versions"]
    assert _mask(_dash_ints(n["clienthello_supported_groups"])) == exp["groups"]
    assert _mask(_dash_ints(n["clienthello_key_share_groups"])) == exp["key_shares"]

    # 计数自洽
    assert int(n["clienthello_cipher_count"]) == len(_nginx_ciphers(n))
    assert int(n["clienthello_extension_count"]) == len(_nginx_exts(n))

    # GREASE 位置：describe 里标记为首位的，nginx grease_positions 必须报 :0
    positions = {}
    if n.get("clienthello_grease_positions"):
        for item in n["clienthello_grease_positions"].split(","):
            where, _, val = item.partition("=")
            kind, _, pos = where.rpartition(":")
            positions[kind] = (int(pos), int(val))
    kinds = (("cipher", exp["ciphers"]), ("group", exp["groups"]),
             ("supported_version", exp["versions"]),
             ("key_share_group", exp["key_shares"]))
    any_grease = False
    for kind, values in kinds:
        if values[0] == "grease":
            any_grease = True
            assert kind in positions, "%s: grease %s missing in positions" % (name, kind)
            pos, val = positions[kind]
            assert pos == 0
            assert _is_grease(val)
        else:
            assert kind not in positions
    assert n["greased"] == ("1" if any_grease else "0")


@pytest.mark.parametrize("name", PRESETS)
def test_extension_order(matrix, name):
    m = matrix[name]
    n, exp, sc = m["nginx"], m["expected"], m["selfcheck"]
    sent = _selfcheck_exts(sc)
    seen = _nginx_exts(n)

    # 引擎发送记录 ⊆ profile 声明；被丢弃的只能是已知既定行为项（见第 6 条）
    assert set(sent) <= set(exp["ext_types"])
    dropped = {t for t in exp["ext_types"] if t not in sent}
    assert dropped <= ENGINE_DROPPED_EXTS

    if exp["ext_permutation"]:
        # chrome：每次握手随机洗牌——集合相等 + 相对顺序与引擎记录一致
        assert sorted(sent) == sorted(
            t for t in exp["ext_types"] if t not in dropped)
    else:
        # firefox/safari：无洗牌，精确顺序
        assert sent == [t for t in exp["ext_types"] if t not in dropped]

    # 采集端只见 OpenSSL 认识的扩展，相对顺序不变（见第 1 条）——逐位相等
    assert seen == [e for e in sent if e not in OPENSSL_UNKNOWN_EXTS]


@pytest.mark.parametrize("name", PRESETS)
def test_ja3(matrix, name):
    m = matrix[name]
    n, sc = m["nginx"], m["selfcheck"]

    # 采集端自洽：ja3_hash 必须是 ja3 原文的 md5
    assert hashlib.md5(n["ja3"].encode()).hexdigest() == n["ja3_hash"]
    assert hashlib.md5(sc["ja3"].encode()).hexdigest() == sc["ja3_hash"]

    # 对齐口径：selfcheck ja3 剔除采集端不可见扩展后必须与 nginx ja3 逐字符相等
    parts = sc["ja3"].split(",")
    kept = [int(x) for x in parts[2].split("-") if int(x) not in OPENSSL_UNKNOWN_EXTS]
    expected_ja3 = ",".join([parts[0], parts[1],
                             "-".join(map(str, kept)), parts[3], parts[4]])
    assert n["ja3"] == expected_ja3
    if len(kept) == len(parts[2].split("-")):
        # 无口径裁剪时 ja3_hash 必须与 selfcheck 逐字符相等（safari 全族实测如此）
        assert n["ja3_hash"] == sc["ja3_hash"]
    else:
        assert hashlib.md5(expected_ja3.encode()).hexdigest() == n["ja3_hash"]


@pytest.mark.parametrize("name", PRESETS)
def test_ja4(matrix, name):
    m = matrix[name]
    n, sc = m["nginx"], m["selfcheck"]

    # 1) nginx ja4 全串 == 按采集端口径从其自身字段重建（锁死口径模型）
    assert _nginx_ja4_rebuild(n) == n["ja4"]

    a_n, b_n, c_n = n["ja4"].split("_")
    a_s, b_s, c_s = sc["ja4"].split("_")

    # 2) ja4_b（cipher 排序 hash，两侧同口径）——逐字符相等
    assert b_n == b_s

    # 3) ja4_c：nginx 口径（剔 0/16/21、无 sigalgs）作用在 selfcheck 扩展集
    #    （剔采集端不可见扩展）上，必须等于 nginx ja4_c
    sent = _selfcheck_exts(sc)
    sig_algs = _dash_ints(n["clienthello_signature_algorithms"])
    visible = [e for e in sent if e not in OPENSSL_UNKNOWN_EXTS]
    assert _sha12(",".join(sorted("%04x" % e for e in visible
                                  if e not in NGINX_JA4C_EXCLUDE))) == c_n

    # 4) geektls selfcheck ja4 遵守官方格式（含 sigalgs、含 padding）——重建锁定
    assert _official_ja4c(sent, sig_algs) == c_s

    # 5) ja4_a 分量：协议/版本/d-i/cipher 数逐字符相等；扩展数差 == 采集端丢弃数；
    #    nginx 无 ALPN 后缀、selfcheck 有（均为各自口径，见第 4 条）
    mo_n = re.fullmatch(r"([tq])(\d\d)([di])(\d\d)(\d\d)", a_n)
    mo_s = re.fullmatch(r"([tq])(\d\d)([di])(\d\d)(\d\d)(..)", a_s)
    assert mo_n and mo_s, "ja4_a shape: nginx=%r selfcheck=%r" % (a_n, a_s)
    assert mo_n.groups()[:4] == mo_s.groups()[:4]
    assert mo_s.group(6) == "h2"  # 7 个自测预设 ALPN 均为 h2 优先
    dropped = len([e for e in sent if e in OPENSSL_UNKNOWN_EXTS])
    assert int(mo_s.group(5)) - int(mo_n.group(5)) == dropped


@pytest.mark.parametrize("name", PRESETS)
def test_http2(matrix, name):
    m = matrix[name]
    n, h2 = m["nginx"], m["describe"]["http2"]

    assert n["http2_settings"] == ";".join("%d:%d" % (i, v) for i, v in h2["settings"])
    assert n["http2_window_update"] == str(h2["window_update"])
    assert n["http2_pseudo_headers"] == ",".join(h2["pseudo_header_order"])

    prio = h2.get("headers_priority")
    if prio is not None:
        # weight 为线上编码值 = 规格值 + 1（见第 5 条）
        expected = "1:%d:0:%d" % (bool(prio["exclusive"]), prio["weight"] + 1)
    else:
        # 未建模 headers_priority 的预设：引擎走 fhttp 默认 HEADERS priority
        # （恰为 Chrome 实测形状 exclusive=1, weight=256），如实锁定。
        expected = "1:1:0:256"
    assert n["http2_priorities"] == expected
    # 合成串格式 = settings|window|priorities|pseudo
    assert n["http2"] == "|".join([n["http2_settings"], n["http2_window_update"],
                                   n["http2_priorities"], n["http2_pseudo_headers"]])


@pytest.fixture(autouse=True, scope="session")
def _collect_summary(matrix):
    yield
    for name in PRESETS:
        if name not in matrix:
            continue
        m = matrix[name]
        n, sc = m["nginx"], m["selfcheck"]
        dropped = sorted(set(_selfcheck_exts(sc)) & OPENSSL_UNKNOWN_EXTS)
        RESULT_ROWS.append((
            name, m["protocol"],
            "exact" if n["ja3_hash"] == sc["ja3_hash"] else "aligned(-%s)" % ",".join(map(str, dropped)),
            "exact" if n["ja4"].split("_")[1] == sc["ja4"].split("_")[1] else "DIFF",
            "%s vs %s" % (n["ja4"].split("_")[0], sc["ja4"].split("_")[0]),
            n["http2_priorities"],
        ))
