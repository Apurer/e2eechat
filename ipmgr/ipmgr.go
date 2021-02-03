package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"crypto/tls"
	"sync"

	"github.com/apurer/e2eechat/dispatch"
	"github.com/apurer/eev"
	"github.com/apurer/ipexc"
	"google.golang.org/protobuf/proto"
)

type remoteAddr struct {
	domain string
	port   string
}

var remAddrSrvTLS remoteAddr
var remAddrSrvHTTPS remoteAddr

const (
	bufferSize = 1024
)

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, bufferSize)
		},
	}

	rulePool = sync.Pool{
		New: func() interface{} {
			return new(dispatch.Rule)
		},
	}
)

func init() {

	privkey := flag.String("key", "", "private key for dencryption of environment variable")
	flag.Parse()

	port, err := eev.Get("TLS_SERVER_PORT", privkey)
	if err != nil {
		panic(err)
	}

	domain, err := eev.Get("TLS_SERVER_DOMAIN", privkey)
	if err != nil {
		panic(err)
	}

	remAddrSrvTLS.port = port
	remAddrSrvTLS.domain = domain

	port, err = eev.Get("HTTPS_SERVER_PORT", privkey)
	if err != nil {
		panic(err)
	}

	domain, err = eev.Get("HTTPS_SERVER_DOMAIN", privkey)
	if err != nil {
		panic(err)
	}

	remAddrSrvHTTPS.port = port
	remAddrSrvHTTPS.domain = domain
}

func main() {

	remTCPAddrSrvHTTPS, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%s", remAddrSrvHTTPS.domain, remAddrSrvHTTPS.port))
	if err != nil {
		log.Print(err)
	}

	// connects via tls and receives incoming requests to modify iptables rules
	remTCPAddrSrvTLS, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%s", remAddrSrvTLS.domain, remAddrSrvTLS.port))
	if err != nil {
		log.Print(err)
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	remConnSrvTLS, err := tls.Dial("tcp", remTCPAddrSrvTLS.String(), conf)
	if err != nil {
		log.Print(err)
		return
	}

	remConnSrvHTTPS, err := tls.Dial("tcp", remTCPAddrSrvHTTPS.String(), conf)
	if err != nil {
		log.Print(err)
		return
	}

	defer remConnSrvTLS.Close()
	defer remConnSrvHTTPS.Close()

	buf := getBuffer()
	defer releaseBuffer(buf)

	for {
		n, err := remConnSrvHTTPS.Read(buf)

		if err != nil {
			break
		}
		if n > 0 {
			rule := rulePool.Get().(*dispatch.Rule)
			err = proto.Unmarshal(buf[:n], rule)
			if err != nil {
				break
			}
			ipexc.Insert(rule.Port, rule.Ip)
			rulePool.Put(rule)
		}
	}

	for {
		n, err := remConnSrvTLS.Read(buf)

		if err != nil {
			break
		}
		if n > 0 {
			rule := rulePool.Get().(*dispatch.Rule)
			err = proto.Unmarshal(buf[:n], rule)
			if err != nil {
				break
			}
			ipexc.Delete(rule.Port, rule.Ip)
			rulePool.Put(rule)
		}
	}
}

func manage(remConnSrvTLS net.Conn, remConnSrvHTTPS net.Conn) {
	insertChan := chanFromConn(remConnSrvTLS)
	deleteChan := chanFromConn(remConnSrvHTTPS)

	for {
		select {
		case insertRule := <-insertChan:
			ipexc.Insert(insertRule.Port, insertRule.Ip)
		case deleteRule := <-deleteChan:
			ipexc.Delete(deleteRule.Port, deleteRule.Ip)
		}
	}
}

func chanFromConn(conn net.Conn) chan *dispatch.Rule {
	c := make(chan *dispatch.Rule)

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
				rule := rulePool.Get().(*dispatch.Rule)
				err = proto.Unmarshal(buf[:n], rule)

				if err != nil {
					break
				}

				c <- rule
				rulePool.Put(rule)
			}
		}
	}()

	return c
}

func getBuffer() []byte {
	return bufferPool.Get().([]byte)
}

func releaseBuffer(b []byte) {
	if len(b) != bufferSize {
		panic("attempted to release buffer with invalid length")
	}
	bufferPool.Put(b)
}
