# geektls 构建脚手架（P0）。
#
# Windows 上 c-shared 只产出 geektls.dll（外加一份 Go 生成的 .h，可忽略——
# 权威头文件是手写的 core/ffi/geektls.h）。绑定层运行时动态加载 DLL，
# 不需要 .dll.a 导入库；如要给原生 C 消费方静态链接，可用 gendef+dlltool
# 从 geektls.dll 生成导入库。
#
# 常用目标：
#   make build   构建动态库到 build/
#   make smoke   构建并跑 Python/Node/Go 三语言冒烟
#   make clean

GO     ?= go
PYTHON ?= python3
NODE   ?= node

CORE  := core
BUILD := build

ifeq ($(OS),Windows_NT)
LIB := geektls.dll
else
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
LIB := libgeektls.dylib
else
LIB := libgeektls.so
endif
endif

LIBPATH := $(BUILD)/$(LIB)

# 绑定层要的是可被宿主进程直接加载的路径；Windows 下转成原生盘符路径。
ifeq ($(OS),Windows_NT)
ABSLIB := $(shell cygpath -w "$(abspath $(LIBPATH))" 2>/dev/null || echo "$(abspath $(LIBPATH))")
else
ABSLIB := $(abspath $(LIBPATH))
endif

.PHONY: all build smoke clean

all: build

# -trimpath -s -w：去掉绝对路径与符号表，动态库体积明显下降（发布包体积直接受益）。
build:
	mkdir -p $(BUILD)
	cd $(CORE) && $(GO) build -buildmode=c-shared -trimpath -ldflags "-s -w" -o ../$(LIBPATH) ./ffi

# wheel：本地出一份"当前平台"的 wheel（发布用；CI 见 .github/workflows/release-pypi.yml）
# 用法：make wheel PLAT=manylinux_2_28_x86_64|macosx_11_0_arm64|win_amd64|...
# ⚠️ 两件事：
#   1) PYTHON 必须是**能装包**的解释器。Debian/Ubuntu 23+ 起系统 python3 受 PEP 668 保护，
#      直接 `make wheel` 会在 `pip install build wheel` 这步失败（externally-managed-environment）
#      ⇒ 用 venv：make wheel PYTHON=.venv/bin/python
#   2) PLAT 是**断言**不是检测：本机（比如 glibc 2.4x 的发行版）构建出的 .so 引用的 GLIBC
#      符号往往高于 manylinux_2_28 基线 ⇒ 本地给 2_28 标签会是"说谎的标签"，
#      只能本地自测用，别拿去上传（v0.1.4 那个多余的 manylinux_2_34 就是这么来的）。
#      真正的 2_28 轮子必须在 manylinux_2_28 容器里构建（CI 的构建步骤）。
PLAT ?= win_amd64
wheel: build
	# 关键清理（与 CI 的"组装 wheel"步一致；0.1.0 踩过两次坑）：
	# 1) setuptools 暂存目录 bindings/python/build/lib/ 会残留旧平台的动态库，
	#    只清包目录不够——它会把别的平台的 .dll/.so 一起打进 wheel；
	# 2) dist 里的旧文件会让后续步骤/上传拿到错的包。
	rm -rf bindings/python/build bindings/python/dist
	rm -f bindings/python/geektls/*.dll bindings/python/geektls/*.so bindings/python/geektls/*.dylib
	cp $(LIBPATH) bindings/python/geektls/
	cp README.md bindings/python/README.md
	cd bindings/python && $(PYTHON) -m pip install --quiet --upgrade build wheel \
		&& $(PYTHON) -m build --wheel \
		&& $(PYTHON) -m wheel tags --remove --platform-tag "$(PLAT)" dist/*.whl \
		&& ls -l dist/

smoke: build
	GEEDTLS_LIB="$(ABSLIB)" $(PYTHON) tests/smoke/smoke.py
	GEEDTLS_LIB="$(ABSLIB)" $(NODE) tests/smoke/smoke.js
	cd tests/smoke && $(GO) run .

clean:
	rm -rf $(BUILD)
