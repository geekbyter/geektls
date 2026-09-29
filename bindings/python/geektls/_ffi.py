"""ctypes 声明层：函数签名与 core/ffi/geektls.h 逐一对齐。

内存约定（docs/02-ffi-abi.md §2）：返回 char* 的函数把所有权移交调用方。
这里一律声明 restype=c_void_p 拿到原始指针，经 take_string() 读取后
立即调 gtls_free_string 释放。

加载搜索顺序：环境变量 GEEDTLS_LIB → 包内 → 仓库 build/ 目录 → 系统路径。
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import sys


def _lib_names() -> list:
    if sys.platform == "win32":
        return ["geektls.dll"]
    if sys.platform == "darwin":
        return ["libgeektls.dylib"]
    return ["libgeektls.so"]


def _candidate_paths():
    env = os.environ.get("GEEDTLS_LIB")
    if env:
        yield env
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    for name in _lib_names():
        yield os.path.join(pkg_dir, name)  # 包内分发
        yield os.path.join(pkg_dir, "..", "..", "..", "build", name)  # 仓库开发态
    found = ctypes.util.find_library("geektls")
    if found:
        yield found
    for name in _lib_names():
        yield name  # 交给加载器默认搜索路径


def _load() -> ctypes.CDLL:
    errors = []
    for path in _candidate_paths():
        try:
            return ctypes.CDLL(path)
        except OSError as exc:
            errors.append("  %s: %s" % (path, exc))
    raise OSError(
        "cannot load the geektls core library; set GEEDTLS_LIB to its path. Tried:\n"
        + "\n".join(errors)
    )


lib = _load()

# --- 签名声明（与 geektls.h 对齐；char* 返回以 c_void_p 接住以便显式释放） ---

lib.gtls_version.restype = ctypes.c_void_p
lib.gtls_version.argtypes = []

lib.gtls_init.restype = ctypes.c_int
lib.gtls_init.argtypes = [ctypes.c_char_p]

lib.gtls_last_error.restype = ctypes.c_void_p
lib.gtls_last_error.argtypes = []

lib.gtls_free_string.restype = None
lib.gtls_free_string.argtypes = [ctypes.c_void_p]

lib.gtls_client_new.restype = ctypes.c_uint64
lib.gtls_client_new.argtypes = [ctypes.c_char_p]

lib.gtls_client_close.restype = ctypes.c_int
lib.gtls_client_close.argtypes = [ctypes.c_uint64]

lib.gtls_session_new.restype = ctypes.c_uint64
lib.gtls_session_new.argtypes = [ctypes.c_uint64, ctypes.c_char_p]

lib.gtls_session_close.restype = ctypes.c_int
lib.gtls_session_close.argtypes = [ctypes.c_uint64]

lib.gtls_request.restype = ctypes.c_uint64
lib.gtls_request.argtypes = [ctypes.c_uint64, ctypes.c_char_p]

lib.gtls_response_info.restype = ctypes.c_void_p
lib.gtls_response_info.argtypes = [ctypes.c_uint64]

lib.gtls_response_read.restype = ctypes.c_int64
lib.gtls_response_read.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int64]

lib.gtls_response_close.restype = ctypes.c_int
lib.gtls_response_close.argtypes = [ctypes.c_uint64]

lib.gtls_request_begin.restype = ctypes.c_uint64
lib.gtls_request_begin.argtypes = [ctypes.c_uint64, ctypes.c_char_p]

lib.gtls_request_write.restype = ctypes.c_int64
lib.gtls_request_write.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int64]

lib.gtls_request_finish.restype = ctypes.c_uint64
lib.gtls_request_finish.argtypes = [ctypes.c_uint64]

lib.gtls_list_presets.restype = ctypes.c_void_p
lib.gtls_list_presets.argtypes = []

lib.gtls_describe_preset.restype = ctypes.c_void_p
lib.gtls_describe_preset.argtypes = [ctypes.c_char_p]

lib.gtls_check_profile.restype = ctypes.c_void_p
lib.gtls_check_profile.argtypes = [ctypes.c_char_p]


def take_string(ptr):
    """读取并释放 core 返回的 char*；NULL 返回 None。"""
    if not ptr:
        return None
    try:
        return ctypes.string_at(ptr).decode("utf-8")
    finally:
        lib.gtls_free_string(ptr)


def take_json(ptr):
    """take_string + JSON 解析。"""
    raw = take_string(ptr)
    return None if raw is None else json.loads(raw)


def last_error() -> dict:
    """当前线程最近错误；无错误返回 {}。"""
    return take_json(lib.gtls_last_error()) or {}
