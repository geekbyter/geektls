"""nginx-l2 终审目录的 pytest 配置：注册 needs_nginx 标记 + 打印对照表。"""

import sys


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "needs_nginx: 需要 WSL2 nginx 指纹采集端（默认 skip，GEEDTLS_NGINX_L2=1 启用）",
    )


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    verify = sys.modules.get("verify_l2")
    rows = getattr(verify, "RESULT_ROWS", None)
    if not rows:
        return
    terminalreporter.write_sep("=", "P1-T8 nginx L2 对照表")
    header = ("preset", "proto", "ja3_hash", "ja4_b", "ja4_a(nginx vs self)", "h2_prio")
    table = [header] + [tuple(r) for r in rows]
    widths = [max(len(str(row[i])) for row in table) for i in range(len(header))]
    for row in table:
        terminalreporter.write_line("  ".join(str(c).ljust(widths[i])
                                             for i, c in enumerate(row)))
