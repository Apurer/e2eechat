package main

import (
	"fmt"
	"log"
	"net"

	"crypto/tls"
	"sync"

	"github.com/apurer/e2eechat/dispatch"
	"github.com/apurer/ipexc"
	"google.golang.org/protobuf/proto"
)

type remoteAddr struct {
	domain string
	port   string
}

var remAddr remoteAddr

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

func main() {
	// connects via tls and receives incoming requests to modify iptables rules

	remTCPAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%s", remAddr.domain, remAddr.port))
	if err != nil {
		log.Print(err)
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	remConn, err := tls.Dial("tcp", remTCPAddr.String(), conf)
	if err != nil {
		log.Print(err)
		return
	}

	defer remConn.Close()

	buf := getBuffer()
	defer releaseBuffer(buf)

	for {
		n, err := remConn.Read(buf)

		if err != nil {
			break
		}
		if n > 0 {
			rule := rulePool.Get().(*dispatch.Rule)
			err = proto.Unmarshal(buf[:n], rule)
			if rule.Insert == true {
				ipexc.Insert(rule.Port, rule.Ip)
			} else {
				ipexc.Delete(rule.Port, rule.Ip)
			}
			rulePool.Put(rule)
		}
	}
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
