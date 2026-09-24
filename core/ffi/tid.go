//go:build cgo

package main

/*
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
static uint64_t gtls_thread_id(void) { return (uint64_t)GetCurrentThreadId(); }
#else
#include <pthread.h>
static uint64_t gtls_thread_id(void) { return (uint64_t)(uintptr_t)pthread_self(); }
#endif
*/
import "C"

// threadID 返回当前 OS 线程 ID，用作线程局部 last error 的 key。
// 本文件不含 //export，因此 preamble 允许带函数定义。
func threadID() uint64 { return uint64(C.gtls_thread_id()) }
