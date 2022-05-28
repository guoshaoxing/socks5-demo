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
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	//成功返回
	return &ClientAuthMessage{
		Version:  SOCKS5Version,
		NMethods: nmethods,
		Methods:  buf,
	}, nil
}

func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	return err
}
