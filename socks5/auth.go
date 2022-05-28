package socks5

import (
	"io"
)

const SOCKS5Version = 0x05

const (
	//methods
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xFF
)

type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}
type Method = byte

func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	// VER: 协议版本，socks5为0x05
	// NMETHODS: 支持认证的方法数量
	// METHODS: 对应NMETHODS，NMETHODS的值为多少，METHODS就有多少个字节。RFC预定义了一些值的含义，内容如下:
	// X’00’ NO AUTHENTICATION REQUIRED
	// X’02’ USERNAME/PASSWORD
	//read version,nMethods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	//validate version
	if buf[0] != SOCKS5Version {
		return nil, ErrVesion
	}
	//read methods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf[:nmethods])
	if err != nil {
		return nil, err
	}
	//成功返回
	return &ClientAuthMessage{
		Version:  SOCKS5Version,
		NMethods: nmethods,
		Methods:  buf[:nmethods],
	}, nil
}

func NewServerAuthMessage(conn io.Writer, method Method) error {
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+

	//对客户端应答
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	return err
}
