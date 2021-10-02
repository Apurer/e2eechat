package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
	"time"

	"github.com/Apurer/e2eechat/dispatch"
	"github.com/golang/protobuf/proto"
)

type remote struct {
	addr string
}

type handler struct {
	proxy *httputil.ReverseProxy
}

const (
	bufferSize = 32 * 1024
)

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, bufferSize)
		},
	}

	authPool = sync.Pool{
		New: func() interface{} {
			return new(dispatch.Authentication)
		},
	}
)

func getBuffer() []byte {
	return bufferPool.Get().([]byte)
}

func releaseBuffer(b []byte) {
	if len(b) != bufferSize {
		panic("attempted to release buffer with invalid length")
	}
	bufferPool.Put(b)
}

func main() {

	tcpProxyPort, tcpServerPort, http2ProxyPort, http2ServerPort := os.Getenv("TCP_PROXY_PORT"), os.Getenv("TCP_SERVER_PORT"), os.Getenv("HTTP2_PROXY_PORT"), os.Getenv("HTTP2_SERVER_PORT")
	if tcpProxyPort == "" {
		log.Fatal("TCP_PROXY_PORT environment variable must be set")
	}
	if tcpServerPort == "" {
		log.Fatal("TCP_SERVER_PORT environment variable must be set")
	}
	if http2ProxyPort == "" {
		log.Fatal("HTTP2_PROXY_PORT environment variable must be set")
	}
	if http2ServerPort == "" {
		log.Fatal("HTTP2_SERVER_PORT environment variable must be set")
	}

	tcpServerRemote := &remote{
		addr: ":" + tcpServerPort,
	}

	http2ServerRemote := &remote{
		addr: ":" + http2ServerPort,
	}

	director := func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = http2ServerRemote.addr
	}

	reverseProxy := &httputil.ReverseProxy{Director: director}
	handler := handler{proxy: reverseProxy}

	proxyTLSCert, proxyTLSKey := os.Getenv("PROXY_TLS_CERT"), os.Getenv("PROXY_TLS_KEY")
	if proxyTLSCert == "" {
		log.Fatal("PROXY_TLS_CERT environment variable must be set")
	}
	if proxyTLSKey == "" {
		log.Fatal("PROXY_TLS_KEY environment variable must be set")
	}

	cer, err := tls.LoadX509KeyPair(proxyTLSCert, proxyTLSKey)
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}

	ln, err := tls.Listen("tcp", tcpProxyPort, config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	log.Printf("Listening: %v -> %v\n\n", tcpProxyPort, tcpServerPort)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
				continue
			}
			go tcpServerRemote.proxyConn(conn)
		}
	}()

	srv := &http.Server{
		Addr:         ":" + http2ProxyPort,
		Handler:      handler,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		TLSConfig:    config,
	}

	log.Fatal(srv.ListenAndServe())
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST","GET":
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Del("X-Forwarded-For")

		h.proxy.ServeHTTP(w, r)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (r *remote) proxyConn(conn net.Conn) {
	defer conn.Close()

	buf := getBuffer()
	defer releaseBuffer(buf)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("handleConnection end: %s\n", conn.RemoteAddr())
		return
	}
	if n > 0 {
		auth := authPool.Get().(*dispatch.Authentication)
		err = proto.Unmarshal(buf[:n], auth) // first check authorization - based on that it will decide whetever it should pass it forward or drop the connection
		authPool.Put(auth)
		// not sure if it should validate within proxy or from main server - maybe here it should only validate object and thats about it on proxy side
		// need to limit database connections
		// if user fails to authenticate just remove iptable rule allowing for connection to proxy
		// if connection drops remove iptable rule allowing for connection to proxy
		if err != nil {
			log.Printf("handleConnection end: %s\n", conn.RemoteAddr())
			return
		}
	}

	rAddr, err := net.ResolveTCPAddr("tcp", r.addr)
	if err != nil {
		log.Print(err)
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	rConn, err := tls.Dial("tcp", rAddr.String(), conf)
	if err != nil {
		log.Print(err)
		return
	}

	defer rConn.Close()

	pipe(conn, rConn)

	log.Printf("handleConnection end: %s\n", conn.RemoteAddr())
}

func chanFromConn(conn net.Conn) chan []byte {
	c := make(chan []byte)

	go func() {
		buf := getBuffer()
		defer releaseBuffer(buf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				c <- nil
				break
			}
			if n > 0 {
				res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, buf[:n])
				c <- res
			}
		}
	}()

	return c
}

func pipe(conn1 net.Conn, conn2 net.Conn) {
	chan1 := chanFromConn(conn1)
	chan2 := chanFromConn(conn2)

	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			}
			conn2.Write(b1)
		case b2 := <-chan2:
			if b2 == nil {
				return
			}
			conn1.Write(b2)
		}
	}
}
