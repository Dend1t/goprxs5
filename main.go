package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
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

	log.Printf("Proxy (SOCKS5 + HTTP) listening on :%s", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, user, pass)
	}
}

func tuneTCP(c net.Conn) {
	if tcpConn, ok := c.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
}

func handleConn(conn net.Conn, user, pass string) {
	defer conn.Close()
	tuneTCP(conn)
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	br := bufio.NewReader(conn)
	peek, err := br.Peek(1)
	if err != nil || len(peek) == 0 {
		return
	}

	if peek[0] == socksVersion5 {
		handleSOCKS5(conn, br, user, pass)
		return
	}

	handleHTTP(conn, br, user, pass)
}

func handleSOCKS5(conn net.Conn, br *bufio.Reader, user, pass string) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != socksVersion5 {
		return
	}

	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
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
	if _, err := io.ReadFull(br, authHdr); err != nil || authHdr[0] != 0x01 {
		return
	}

	uBuf := make([]byte, int(authHdr[1]))
	if _, err := io.ReadFull(br, uBuf); err != nil {
		return
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(br, pLenBuf); err != nil {
		return
	}
	pBuf := make([]byte, int(pLenBuf[0]))
	if _, err := io.ReadFull(br, pBuf); err != nil {
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
	if _, err := io.ReadFull(br, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != socksVersion5 || reqHdr[1] != cmdConnect {
		_ = sendSOCKSReply(conn, 0x07)
		return
	}

	var host string
	switch reqHdr[3] {
	case addrIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case addrDomain:
		dLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(br, dLenBuf); err != nil {
			return
		}
		dBuf := make([]byte, int(dLenBuf[0]))
		if _, err := io.ReadFull(br, dBuf); err != nil {
			return
		}
		host = string(dBuf)
	case addrIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		_ = sendSOCKSReply(conn, 0x08)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", targetPort))

	_ = conn.SetDeadline(time.Time{})

	remote, err := (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial("tcp", targetAddr)
	if err != nil {
		_ = sendSOCKSReply(conn, 0x05)
		return
	}
	defer remote.Close()
	tuneTCP(remote)

	if err := sendSOCKSReply(conn, 0x00); err != nil {
		return
	}

	relayBuffered(conn, br, remote)
}

func handleHTTP(conn net.Conn, br *bufio.Reader, user, pass string) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()

	if !checkBasicAuth(req.Header.Get("Proxy-Authorization"), user, pass) {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}

	_ = conn.SetDeadline(time.Time{})

	if strings.EqualFold(req.Method, http.MethodConnect) {
		targetAddr := req.Host
		if !strings.Contains(targetAddr, ":") {
			targetAddr = net.JoinHostPort(targetAddr, "443")
		}

		remote, err := (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial("tcp", targetAddr)
		if err != nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		defer remote.Close()
		tuneTCP(remote)

		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}

		relayBuffered(conn, br, remote)
		return
	}

	targetAddr := req.Host
	if !strings.Contains(targetAddr, ":") {
		targetAddr = net.JoinHostPort(targetAddr, "80")
	}

	remote, err := (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial("tcp", targetAddr)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	defer remote.Close()
	tuneTCP(remote)

	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	if req.URL != nil && req.URL.Path == "" {
		req.URL.Path = "/"
	}

	if err := req.Write(remote); err != nil {
		return
	}
	_, _ = io.Copy(conn, remote)
}

func checkBasicAuth(headerVal, user, pass string) bool {
	if !strings.HasPrefix(headerVal, "Basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(headerVal, "Basic ")))
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	return len(parts) == 2 && parts[0] == user && parts[1] == pass
}

func relayBuffered(clientConn net.Conn, clientReader *bufio.Reader, remoteConn net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		if clientReader.Buffered() > 0 {
			_, _ = io.CopyN(remoteConn, clientReader, int64(clientReader.Buffered()))
		}
		_, _ = io.Copy(remoteConn, clientConn)
		if tcpRemote, ok := remoteConn.(*net.TCPConn); ok {
			_ = tcpRemote.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(clientConn, remoteConn)
		if tcpClient, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpClient.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
}

func sendSOCKSReply(conn net.Conn, rep byte) error {
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
