package main

import (
	"log"

	"github.com/GuoShaoxing/socks5-demo/socks5"
)

func main() {
	server := socks5.Socks5Server{
		IP:   "localhost",
		Port: 1080,
	}
	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}
