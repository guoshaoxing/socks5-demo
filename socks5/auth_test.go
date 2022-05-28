package socks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClientAuthMessage(t *testing.T) {
	t.Run("should generate a message", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, 0x00, 0x01}
		r := bytes.NewReader(b)

		message, err := NewClientAuthMessage(r)
		if err != nil {
			t.Fatalf("want error = nil but got %s", err)
		}
		if message.Version != SOCKS5Version {
			t.Fatalf("want Socks5version but got %d", message.Version)
		}
		if message.NMethods != 2 {
			t.Fatalf("want nmethod = 2 but got %d", message.NMethods)
		}
		if !reflect.DeepEqual(message.Methods, []byte{0x00, 0x01}) {
			t.Fatalf("want method %v  but got %v", []byte{0x00, 0x01}, message.NMethods)
		}
	})
}

func TestNewServerAuthMessage(t *testing.T) {
	t.Run("should pass", func(t *testing.T) {
		var buf bytes.Buffer

		err := NewServerAuthMessage(&buf, MethodNoAuth)
		if err != nil {
			t.Fatalf("should get nil but got %s", err)
		}
		got := buf.Bytes()
		if !reflect.DeepEqual(got, []byte{SOCKS5Version, MethodNoAuth}) {
			t.Fatalf("should send %v but got %v", []byte{SOCKS5Version, MethodNoAuth}, got)
		}
	})

}
