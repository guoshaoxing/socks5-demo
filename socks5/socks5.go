package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

type Server interface {
	Run() error
}

type Socks5Server struct {
	IP   string
	Port int
}

var (
	ErrVesion  = errors.New("protocol version not supported")
	ErrCmd     = errors.New("requst command not supported")
	ErrRSV     = errors.New("invalid reserved field")
	ErrAddress = errors.New("address type not supported")
)

func (s *Socks5Server) Run() error {
	//监听
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.IP, s.Port))
	if err != nil {
		return err
	}

	for {
		//连接
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("conn server is failure from  %s  %s", conn.RemoteAddr(), err)
			continue
		}
		//处理
		go func() {
			defer conn.Close()
			err := handleConnection(conn)
			if err != nil {
				log.Printf("handleConnection server is failure from  %s  %s", conn.RemoteAddr(), err)
			}
		}()
	}
}
func handleConnection(conn net.Conn) error {
	//协商
	if err := auth(conn); err != nil {
		return err
	}
	//请求
	targetConn, err := request(conn)
	if err != nil {
		return err
	}
	//转发
	err = forword(conn, targetConn)
	return err
}

func auth(conn net.Conn) error {
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}
	// log.Println(clientMessage.Version, clientMessage.NMethods, clientMessage.Methods)

	//only support no-auth
	var acceptable bool
	for _, method := range clientMessage.Methods {
		if method == MethodNoAuth {
			acceptable = true
		}
	}
	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not supported")
	}

	return NewServerAuthMessage(conn, MethodNoAuth)
}

func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	msg, err := NewClientRequestMessage(conn)
	if err != nil {
		return nil, err
	}
	if msg.Cmd != CmdConnect { //客户端请求的cmd不是tcp的connect
		return nil, WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
	}
	if msg.Atpy != TypeIPv4 { //客户端请求的地址类型不是ipv4
		return nil, WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
	}
	//请求访问目标TCP
	address := fmt.Sprintf("%s:%d", msg.Address, msg.Port)
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, WriteRequestFailureMessage(conn, ReplyConnectionRefused)
	}
	//send success reply
	addrVal := targetConn.LocalAddr()
	addr := addrVal.(*net.TCPAddr)
	return targetConn, WriteRequestSucessMessage(conn, addr.IP, uint16(addr.Port))
}
func forword(conn io.ReadWriter, targetConn io.ReadWriteCloser) error {
	defer targetConn.Close()
	go io.Copy(targetConn, conn)
	_, err := io.Copy(conn, targetConn)
	return err
}
