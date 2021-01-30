package main

import (
	"log"
	"github.com/golang/protobuf/proto"
	"github.com/apurer/e2eechat/datatypes"
	"crypto/tls"
	"sync"
	"net"
)

const (
	bufferSize = 32 * 1024
)

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, bufferSize)
		},
	}

	messagePool = sync.Pool{
		New: func() interface{} {
			 return new(message.Message)
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

const localAddr string = ":25500"
const remoteAddr string = "127.0.0.1:25501"

func main() {
	log.SetFlags(log.Lshortfile)

	cer, err := tls.LoadX509KeyPair("proxy.crt", "proxy.key")
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", localAddr, config) 
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	log.Printf("Listening: %v -> %v\n\n", localAddr, remoteAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go proxyConn(conn)
	}
}

func proxyConn(conn net.Conn) {
	defer conn.Close()

	buf := getBuffer()
	defer releaseBuffer(buf)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("handleConnection end: %s\n", conn.RemoteAddr())
		return
	}
	if n > 0 {
		messagePb := message.Message{}
		err = proto.Unmarshal(buf[:n], &messagePb) // first check authorization - based on that it will decide whetever it should pass it forward or drop the connection
		// not sure if it should validate within proxy or from main server - maybe here it should only validate object and thats about it on proxy side
		// need to limit database connections 
		// if user fails to authenticate just remove iptable rule allowing for connection to proxy 
		// if connection drops remove iptable rule allowing for connection to proxy
		if err != nil {
			log.Printf("handleConnection end: %s\n", conn.RemoteAddr())
			return
		}
		log.Printf("first message: %s, timestamp: %v", messagePb.Text, messagePb.Timestamp)
	}

	rAddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		log.Print(err)
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	//rConn, err := net.DialTCP("tcp", nil, rAddr)
	rConn, err := tls.Dial("tcp", rAddr.String(), conf)
	if err != nil {
		log.Print(err)
		return
	}

	defer rConn.Close()

	Pipe(conn, rConn)

	log.Printf("handleConnection end: %s\n", conn.RemoteAddr())
}

func chanFromConnServer(conn net.Conn) chan []byte {
	c := make(chan []byte)

	go func() {
		//buf := make([]byte, 1024)
		buf := getBuffer()
		defer releaseBuffer(buf)

		for {
			n, err := conn.Read(buf)
			if n > 0 {
				res := make([]byte, n)
				//messagePb := message.Message{}
				// err = proto.Unmarshal(buf[:n], &message.Message{})
				// if err != nil {
				// 	conn.Close()
				// 	//log.Print("breaking")
				// 	break
				// }
				//log.Printf("intercepted message: %s, timestamp: %v", messagePb.Text, messagePb.Timestamp)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, buf[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				break
			}
		}
	}()

	return c
}

func chanFromConnClient(conn net.Conn) chan []byte {
	c := make(chan []byte)

	go func() {
		//buf := make([]byte, 1024)
		buf := getBuffer()
		defer releaseBuffer(buf)

		for {
			n, err := conn.Read(buf)
			if n > 0 {
				res := make([]byte, n)
				messagePb := message.Message{}
				//err = proto.Unmarshal(buf[:n], &message.Message{})
				err = proto.Unmarshal(buf[:n], &messagePb)
				if err != nil {
					//conn.Close()
					c <- nil
					//log.Print("breaking")
					break
				}
				log.Printf("intercepted message: %s, timestamp: %v", messagePb.Text, messagePb.Timestamp)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, buf[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				break
			}
		}
	}()

	return c
}

func Pipe(conn1 net.Conn, conn2 net.Conn) {
	chan1 := chanFromConnClient(conn1)
	chan2 := chanFromConnServer(conn2)

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