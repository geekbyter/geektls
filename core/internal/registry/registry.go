// Package registry 提供跨 ABI 对象的 uint64 handle 注册表（docs/02-ffi-abi.md §2）。
package registry

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// ErrNotFound 在操作未知或已关闭的 handle 时返回（close 幂等：报错不 panic）。
var ErrNotFound = errors.New("registry: unknown handle")

// Registry 是并发安全的 handle 表。handle 从 1 开始分配，0 保留为"无效"。
type Registry struct {
	next atomic.Uint64
	m    sync.Map
}

func New() *Registry { return &Registry{} }

// Register 存储 v 并返回新 handle。
func (r *Registry) Register(v any) uint64 {
	id := r.next.Add(1)
	r.m.Store(id, v)
	return id
}

// Get 取出 handle 对应的对象，不做类型断言（由调用方校验种类）。
func (r *Registry) Get(id uint64) (any, bool) { return r.m.Load(id) }

// Delete 移除 handle；重复删除返回 ErrNotFound 而不是 panic。
func (r *Registry) Delete(id uint64) error {
	if _, loaded := r.m.LoadAndDelete(id); !loaded {
		return fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	return nil
}
