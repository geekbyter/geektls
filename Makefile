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

build:
	mkdir -p $(BUILD)
	cd $(CORE) && $(GO) build -buildmode=c-shared -o ../$(LIBPATH) ./ffi

smoke: build
	GEEDTLS_LIB="$(ABSLIB)" $(PYTHON) tests/smoke/smoke.py
	GEEDTLS_LIB="$(ABSLIB)" $(NODE) tests/smoke/smoke.js
	cd tests/smoke && $(GO) run .

clean:
	rm -rf $(BUILD)
