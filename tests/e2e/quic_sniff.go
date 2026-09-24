package e2e

// QUIC Initial 嗅探器（P4-T4/T6 验收工具）：
// RFC 9001 v1 规定 Initial 用"对 DCID 可推导的公开密钥"加密，任何旁观者
// 都能解密——所以本地 UDP 嗅探即可拿到客户端真实发出的 transport params
// 与 ClientHello 字节，无需依赖 quic-go 内部钩子（peerParams 不导出）。
//
// 注意 ClientHello 常被分片进多个 CRYPTO 帧（跨多个 Initial 包），
// 需要按 (offset, data) 重组 crypto 流。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/hkdf"

	"github.com/geektls/core/profiles"
)

var initialSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

type varintReader struct {
	b   []byte
	pos int
}

func (r *varintReader) read() (uint64, error) {
	if r.pos >= len(r.b) {
		return 0, fmt.Errorf("varint: eof")
	}
	n := 1 << (r.b[r.pos] >> 6) // 顶 2 位编码长度
	if len(r.b)-r.pos < n {
		return 0, fmt.Errorf("varint: truncated")
	}
	v := uint64(r.b[r.pos] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(r.b[r.pos+i])
	}
	r.pos += n
	return v, nil
}

func (r *varintReader) take(n int) ([]byte, error) {
	if n < 0 || len(r.b)-r.pos < n {
		return nil, fmt.Errorf("take %d: truncated", n)
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	info := []byte{0, byte(length), byte(6 + len(label)), 't', 'l', 's', '1', '3', ' '}
	info = append(info, label...)
	info = append(info, 0)
	out := make([]byte, length)
	r := hkdf.Expand(sha256.New, secret, info)
	if _, err := r.Read(out); err != nil {
		panic(err)
	}
	return out
}

type quicInitialKeys struct {
	key, iv, hp []byte
}

func initialKeys(dcid []byte) quicInitialKeys {
	initialSecret := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	return quicInitialKeys{
		key: hkdfExpandLabel(clientSecret, "quic key", 16),
		iv:  hkdfExpandLabel(clientSecret, "quic iv", 12),
		hp:  hkdfExpandLabel(clientSecret, "quic hp", 16),
	}
}

// initialPacket 是解密后的一个 Initial 包。
type initialPacket struct {
	PacketNumber uint64
	CryptoChunks [][2]int // 在本包 payload 里的 crypto chunk 索引（offset 见 CryptoFrames）
	CryptoFrames []cryptoFrame
	NextOffset   int // 本包在 datagram 中的结束位置
}

type cryptoFrame struct {
	Offset uint64
	Data   []byte
}

// decryptInitialAt 解密 datagram 中 off 处的一个 Initial 包。
// 返回 nil,nil 表示该处不是 Initial 包（例如 coalesce 的 Handshake 包——密钥不同，跳过）。
func decryptInitialAt(dgram []byte, off int, keys quicInitialKeys) (*initialPacket, error) {
	if len(dgram)-off < 7 || dgram[off]&0x80 == 0 {
		return nil, fmt.Errorf("not a long-header packet at %d", off)
	}
	// 长头 v1 类型位：0xC0=Initial, 0xD0=0-RTT, 0xE0=Handshake, 0xF0=Retry
	pktType := dgram[off] & 0x30
	version := binary.BigEndian.Uint32(dgram[off+1 : off+5])
	if version != 1 {
		return nil, fmt.Errorf("quic version %#08x, want v1", version)
	}

	r := &varintReader{b: dgram, pos: off + 5}
	dcidLen, err := r.read() // DCID len 是单字节（在头格式里是固定 1 字节）
	if err != nil {
		return nil, err
	}
	r.pos = off + 5 // DCID/SCID 长度字段是裸字节，不是 varint
	r.pos++
	dcid, err := r.take(int(dcidLen))
	_ = dcid
	if err != nil {
		return nil, err
	}
	scidLenByte, err := r.take(1)
	if err != nil {
		return nil, err
	}
	if _, err := r.take(int(scidLenByte[0])); err != nil {
		return nil, err
	}

	if pktType == 0x00 { // Initial 才有 token 字段
		tokenLen, err := r.read()
		if err != nil {
			return nil, err
		}
		if _, err := r.take(int(tokenLen)); err != nil {
			return nil, err
		}
	}
	length, err := r.read()
	if err != nil {
		return nil, err
	}
	pnOffset := r.pos

	if pktType != 0x00 {
		// 非 Initial：只跳过（长度字段 = pn + payload）
		return &initialPacket{NextOffset: pnOffset + int(length)}, nil
	}

	if len(dgram) < pnOffset+4+16 {
		return nil, fmt.Errorf("datagram too short for hp sample")
	}
	sample := dgram[pnOffset+4 : pnOffset+4+16]
	hpCipher, _ := aes.NewCipher(keys.hp)
	mask := make([]byte, 16)
	hpCipher.Encrypt(mask, sample)

	hdr := make([]byte, pnOffset-off+4)
	copy(hdr, dgram[off:pnOffset+4])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		b := dgram[pnOffset+i] ^ mask[1+i]
		pn = pn<<8 | uint64(b)
		hdr[pnOffset-off+i] = b
	}

	payloadLen := int(length) - pnLen
	if len(dgram) < pnOffset+pnLen+payloadLen {
		return nil, fmt.Errorf("payload truncated")
	}
	ciphertext := dgram[pnOffset+pnLen : pnOffset+pnLen+payloadLen]

	aead, err := cipher.NewGCM(mustAES(keys.key))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce, keys.iv)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	plain, err := aead.Open(nil, nonce, ciphertext, hdr[:pnOffset-off+pnLen])
	if err != nil {
		return nil, fmt.Errorf("initial decrypt: %w", err)
	}

	pkt := &initialPacket{
		PacketNumber: pn,
		NextOffset:   pnOffset + pnLen + payloadLen,
	}
	fr := &varintReader{b: plain}
	for fr.pos < len(plain) {
		ftype, err := fr.read()
		if err != nil {
			return nil, err
		}
		switch ftype {
		case 0x00, 0x01: // PADDING / PING
			continue
		case 0x06: // CRYPTO
			coff, err := fr.read()
			if err != nil {
				return nil, err
			}
			n, err := fr.read()
			if err != nil {
				return nil, err
			}
			data, err := fr.take(int(n))
			if err != nil {
				return nil, err
			}
			cp := make([]byte, len(data))
			copy(cp, data)
			pkt.CryptoFrames = append(pkt.CryptoFrames, cryptoFrame{Offset: coff, Data: cp})
		default:
			// ACK 等：本嗅探器只关心 CRYPTO，遇未知帧停止解析本包
			return pkt, nil
		}
	}
	return pkt, nil
}

func mustAES(key []byte) cipher.Block {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return c
}

// cryptoStreamReassembler 按 offset 重组 CRYPTO 流。
type cryptoStreamReassembler struct {
	chunks []cryptoFrame
}

func (c *cryptoStreamReassembler) add(f cryptoFrame) { c.chunks = append(c.chunks, f) }

// assembled 返回已重组的前缀长度；完整时 data 为全部字节。
func (c *cryptoStreamReassembler) assembled() (data []byte, totalNeeded int, complete bool) {
	var out []byte
	for {
		var next *cryptoFrame
		for i := range c.chunks {
			if c.chunks[i].Offset == uint64(len(out)) {
				next = &c.chunks[i]
				break
			}
		}
		if next == nil {
			break
		}
		out = append(out, next.Data...)
	}
	if len(out) >= 4 {
		totalNeeded = 4 + int(out[1])<<16 + int(out[2])<<8 + int(out[3])
		complete = len(out) >= totalNeeded
	}
	return out, totalNeeded, complete
}

// parseQUICTransportParams 解析 QUIC transport parameters 扩展（type 57）负载。
func parseQUICTransportParams(data []byte) (map[uint64][]byte, error) {
	out := map[uint64][]byte{}
	r := &varintReader{b: data}
	for r.pos < len(data) {
		id, err := r.read()
		if err != nil {
			return nil, err
		}
		n, err := r.read()
		if err != nil {
			return nil, err
		}
		v, err := r.take(int(n))
		if err != nil {
			return nil, fmt.Errorf("tp %#x truncated", id)
		}
		out[id] = v
	}
	return out, nil
}

// clientHelloFromCrypto 把重组后的 TLS ClientHello 包上假 record 头，
// 复用 profiles.FromClientHelloHex 解析。
func clientHelloFromCrypto(crypto []byte) (*profiles.Profile, error) {
	if len(crypto) < 4 || crypto[0] != 1 {
		return nil, fmt.Errorf("not a client_hello handshake message")
	}
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(crypto) >> 8), byte(len(crypto))}, crypto...)
	p, _, err := profiles.FromClientHelloHex(hex.EncodeToString(rec))
	return p, err
}
