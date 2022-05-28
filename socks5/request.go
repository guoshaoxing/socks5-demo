package socks5

import (
	"io"
	"net"
)

type ClientRequestMessage struct {
	// Version byte
	Cmd     Command
	Atpy    byte
	Address string
	Port    uint16
}

type Command = byte

const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03
)
const ReservedField = 0x00

type AddressType = byte

const (
	TypeIPv4   AddressType = 0x01
	TypeDomain AddressType = 0x03
	TypeIPv6   AddressType = 0x04
)

func NewClientRequestMessage(conn io.Reader) (*ClientRequestMessage, error) {
	buf := make([]byte, 4)
	_, err := io.ReadFull(conn, buf) //get version , cmd , rsv , atyp
	if err != nil {
		return nil, err
	}
	version, cmd, atyp := buf[0], buf[1], buf[3]
	//check version,cmd,rsv,atyp
	if version != SOCKS5Version {
		return nil, ErrVesion
	}
	if cmd != CmdConnect && cmd != CmdBind && cmd != CmdUDP {
		return nil, ErrCmd
	}
	if atyp != TypeIPv4 && atyp != TypeDomain && atyp != TypeIPv6 {
		return nil, ErrAddress
	}
	message := ClientRequestMessage{
		Cmd:  cmd,
		Atpy: atyp,
	}
	//read address
	switch atyp {
	case TypeIPv6:
		buf = make([]byte, 16)
		fallthrough
	case TypeIPv4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf)
		message.Address = ip.String()
	case TypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		domainLen := buf[0]
		if domainLen > 4 {
			buf = make([]byte, domainLen)
		}
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return nil, err
		}
		message.Address = string(buf[:domainLen])
	}
	//read port
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}
	message.Port = (uint16(buf[0]) << 8) + uint16(buf[1])
	return &message, nil
}

type ReplyType = byte

const (
	ReplySuccess ReplyType = iota
	ReplyServerFailure
	ReplyConnectionNotAllowed
	ReplyNetWorkUnreachable
	ReplyHostUnreachable
	ReplyConnectionRefused
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTypeNotSupported
)

func WriteRequestSucessMessage(conn io.Writer, ip net.IP, port uint16) error {
	addressType := TypeIPv4
	if len(ip) == 16 {
		addressType = TypeIPv6
	}
	//write version,reply,rsv,atype
	_, err := conn.Write([]byte{SOCKS5Version, ReplySuccess, ReservedField, addressType})
	if err != nil {
		return err
	}
	//write bind ip
	if _, err = conn.Write(ip); err != nil {
		return err
	}
	//write bind port
	buf := make([]byte, 2)
	buf[0] = byte(port >> 8)
	buf[1] = byte(port - uint16(buf[0])<<8)
	_, err = conn.Write(buf)
	return err
}
func WriteRequestFailureMessage(conn io.Writer, replyType ReplyType) error {
	_, err := conn.Write([]byte{SOCKS5Version, replyType, ReservedField, TypeIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
