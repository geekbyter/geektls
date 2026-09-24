// Package tlscore 封装 uTLS：ClientHello 构造与握手。
//
// 目录名为 core/tls 但包名刻意叫 tlscore，避免与标准库 crypto/tls 混淆。
// P1-T1 仅为集成基线：默认 HelloChrome_Auto 预设；逐字段控制在 P1-T2 落地。
package tlscore

import (
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DefaultDialTimeout 是 Dial 的默认 TCP 连接超时。
const DefaultDialTimeout = 10 * time.Second

// Handshake 在已建立的 conn 上以 uTLS 完成一次客户端握手。
//
// cfg 为 nil 时使用空配置（调用方通常至少要设置 ServerName）；
// spec 为 nil 时使用 utls.HelloChrome_Auto 预设，否则套用给定 ClientHelloSpec。
// 返回的 UConn 已完成握手，可直接读写；失败时 conn 由调用方关闭。
//
// 注意：自定义 spec 必须以 utls.HelloCustom 为基底——用浏览器预设 ID 时
// uTLS 会在 Handshake 时重新 applyPresetByID 覆盖掉自定义 spec（实测坑）。
func Handshake(conn net.Conn, cfg *utls.Config, spec *utls.ClientHelloSpec) (*utls.UConn, error) {
	if cfg == nil {
		cfg = &utls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	// 空 PSK 扩展（无票据的占位）线上省略——Chrome 语义；不设的话带
	// pre_shared_key 占位的 spec 在无票据时会被 uTLS 报错。
	cfg.OmitEmptyPsk = true
	helloID := utls.HelloChrome_Auto
	if spec != nil {
		helloID = utls.HelloCustom
	}
	uconn := utls.UClient(conn, cfg, helloID)
	if spec != nil {
		if err := uconn.ApplyPreset(spec); err != nil {
			return nil, err
		}
	}
	if err := uconn.Handshake(); err != nil {
		return nil, err
	}
	return uconn, nil
}

// Dial 建立 TCP 连接并在其上完成 uTLS 握手；任一步失败都会关闭底层连接。
func Dial(addr string, cfg *utls.Config, spec *utls.ClientHelloSpec) (*utls.UConn, error) {
	conn, err := net.DialTimeout("tcp", addr, DefaultDialTimeout)
	if err != nil {
		return nil, err
	}
	uconn, err := Handshake(conn, cfg, spec)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return uconn, nil
}
