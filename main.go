package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

const (
	socksVersion5 = 0x05
	authUserPass   = 0x02
	authNoAccept   = 0xFF
	cmdConnect     = 0x01
	addrIPv4       = 0x01
	addrDomain     = 0x03
	addrIPv6       = 0x04
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	port := getEnv("PORT", "8080")
	user := getEnv("PROXY_USER", "user")
	pass := getEnv("PROXY_PASS", "pass")

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	defer ln.Close()

	log.Printf("SOCKS5 listening on :%s", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, user, pass)
	}
}

func tuneTCP(c net.Conn) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
}

func handleClient(conn net.Conn, user, pass string) {
	defer conn.Close()
	tuneTCP(conn)

	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != socksVersion5 {
		return
	}

	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	supportsAuth := false
	for _, m := range methods {
		if m == authUserPass {
			supportsAuth = true
			break
		}
	}
	if !supportsAuth {
		_, _ = conn.Write([]byte{socksVersion5, authNoAccept})
		return
	}

	if _, err := conn.Write([]byte{socksVersion5, authUserPass}); err != nil {
		return
	}

	authHdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, authHdr); err != nil || authHdr[0] != 0x01 {
		return
	}

	uLen := int(authHdr[1])
	uBuf := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uBuf); err != nil {
		return
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return
	}
	pLen := int(pLenBuf[0])
	pBuf := make([]byte, pLen)
	if _, err := io.ReadFull(conn, pBuf); err != nil {
		return
	}

	if string(uBuf) != user || string(pBuf) != pass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return
	}

	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != socksVersion5 || reqHdr[1] != cmdConnect {
		_ = sendReply(conn, 0x07)
		return
	}

	var host string
	switch reqHdr[3] {
	case addrIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case addrDomain:
		dLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, dLenBuf); err != nil {
			return
		}
		dBuf := make([]byte, int(dLenBuf[0]))
		if _, err := io.ReadFull(conn, dBuf); err != nil {
			return
		}
		host = string(dBuf)
	case addrIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		_ = sendReply(conn, 0x08)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", targetPort))

	// Снимаем дедлайн рукопожатия и даём отдельный таймаут только на подключение к цели
	_ = conn.SetDeadline(time.Time{})

	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	remote, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		_ = sendReply(conn, 0x05)
		return
	}
	defer remote.Close()
	tuneTCP(remote)

	if err := sendReply(conn, 0x00); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go relayHalf(remote, conn, done)
	go relayHalf(conn, remote, done)
	<-done
}

func relayHalf(dst, src net.Conn, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	if tcpDst, ok := dst.(*net.TCPConn); ok {
		_ = tcpDst.CloseWrite()
	}
	if tcpSrc, ok := src.(*net.TCPConn); ok {
		_ = tcpSrc.CloseRead()
	}
	done <- struct{}{}
}

func sendReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{
		socksVersion5,
		rep,
		0x00,
		addrIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	})
	return err
}
