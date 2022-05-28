package socks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestNewClientRequestMessage(t *testing.T) {
	//创建测试用例
	tests := []struct {
		Cmd      Command
		AddrType AddressType
		Address  []byte
		Port     []byte
		Err      error
		Message  ClientRequestMessage
	}{
		{
			Cmd:      CmdConnect,
			AddrType: TypeIPv4,
			Address:  []byte{123, 35, 12, 34},
			Port:     []byte{0x00, 0x50},
			Err:      nil,
			Message: ClientRequestMessage{
				Cmd:     CmdConnect,
				Address: "123.35.12.34",
				Port:    0x0050,
			},
		},
	}

	for _, test := range tests {
		//填写流
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5Version, test.Cmd, ReservedField, test.AddrType})
		buf.Write(test.Address)
		buf.Write(test.Port)
		//测试
		msg, err := NewClientRequestMessage(&buf)
		if err != test.Err {
			t.Fatalf("should get error %s but got %s", test.Err, err)
		}
		if !reflect.DeepEqual(*msg, test.Message) {
			t.Fatalf("should get message %v,but got %v", test.Message, msg)
		}
	}
}

func TestWriteRequestSucessMessage(t *testing.T) {
	var buf bytes.Buffer
	ip := net.IP([]byte{123, 12, 23, 23})
	port := 1080
	err := WriteRequestSucessMessage(&buf, ip, uint16(port))
	if err != nil {
		t.Fatalf("error while writing %s", err)
	}
	//查看是否成功返回
	want := []byte{SOCKS5Version, ReplySuccess, ReservedField, TypeIPv4, 123, 12, 23, 23, 0x04, 0x38}
	got := buf.Bytes()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("message not match : want %v but got %v", want, got)
	}
}
