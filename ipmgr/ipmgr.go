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

func (remAddr remoteAddr) resolveTCPAddrAndConnect(conf *tls.Config) (*tls.Conn, error) {

	remTCPAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%s", remAddr.domain, remAddr.port))
	if err != nil {
		log.Print(err)
		return nil, err
	}

	remConn, err := tls.Dial("tcp", remTCPAddr.String(), conf)
	if err != nil {
		log.Print(err)
		return nil, err
	}

	return remConn, nil
}

func main() {

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	remConnSrvHTTPS, err := remAddrSrvHTTPS.resolveTCPAddrAndConnect(conf)
	if err != nil {
		log.Print(err)
		return
	}

	// connects via tls and receives incoming requests to modify iptables rules
	remConnSrvTLS, err := remAddrSrvTLS.resolveTCPAddrAndConnect(conf)
	if err != nil {
		log.Print(err)
		return
	}

	defer remConnSrvTLS.Close()
	defer remConnSrvHTTPS.Close()

	manage(remConnSrvTLS, remConnSrvHTTPS)
}

func manage(remConnSrvTLS net.Conn, remConnSrvHTTPS net.Conn) {
	insertRuleChan := chanFromConn(remConnSrvTLS)
	deleteRuleChan := chanFromConn(remConnSrvHTTPS)

	for {
		select {
		case b1 := <-insertRuleChan:
			if b1 == nil {
				return
			}
			insertRule := rulePool.Get().(*dispatch.Rule)
			defer rulePool.Put(insertRule)
			err := proto.Unmarshal(b1, insertRule)
			if err != nil {
				return
			}
			ipexc.Insert(insertRule.Port, insertRule.Ip)
		case b2 := <-deleteRuleChan:
			if b2 == nil {
				return
			}
			deleteRule := rulePool.Get().(*dispatch.Rule)
			defer rulePool.Put(deleteRule)
			err := proto.Unmarshal(b2, deleteRule)
			if err != nil {
				return
			}
			ipexc.Delete(deleteRule.Port, deleteRule.Ip)
		}
	}
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

func getBuffer() []byte {
	return bufferPool.Get().([]byte)
}

func releaseBuffer(b []byte) {
	if len(b) != bufferSize {
		panic("attempted to release buffer with invalid length")
	}
	bufferPool.Put(b)
}
