package main

import (
	"github.com/apurer/ipexc"
)

func main() {
	port := "8080"
	ip := "127.0.0.1"
	ipexc.Insert(port, ip)
}
