package main

import (
	"net"

	"github.com/pion/mdns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func main() {
	test6()
	//test4()
}

func test4() {
	addr, err := net.ResolveUDPAddr("udp", mdns.DefaultAddress)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUDP("udp4", addr)
	if err != nil {
		panic(err)
	}

	_, err = mdns.Server(ipv4.NewPacketConn(l), &mdns.Config{
		LocalNames: []string{"pion-test.local"},
	})
	if err != nil {
		panic(err)
	}
	select {}
}

func test6() {
	addr, err := net.ResolveUDPAddr("udp6", mdns.DefaultAddress6)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUDP("udp6", addr)
	if err != nil {
		panic(err)
	}

	_, err = mdns.Server6(ipv6.NewPacketConn(l), &mdns.Config{
		LocalNames: []string{"pion-test.local"},
	})
	if err != nil {
		panic(err)
	}
	select {}
}
