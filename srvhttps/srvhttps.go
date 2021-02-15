package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/Apurer/eev"
)

type localAddr struct {
	domain string
	port   string
}

var lclAddr localAddr

func (l *localAddr) redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, fmt.Sprintf("https://%s:%s%s", l.domain, l.port, r.RequestURI), http.StatusMovedPermanently)
}

func init() {

	privkey := flag.String("key", "", "private key for dencryption of environment variable")
	flag.Parse()

	port, err := eev.Get("HTTPS_SERVER_PORT", []byte(*privkey))
	if err != nil {
		panic(err)
	}

	domain, err := eev.Get("HTTPS_SERVER_DOMAIN", []byte(*privkey))
	if err != nil {
		panic(err)
	}

	lclAddr.port = port
	lclAddr.domain = domain
}

func main() {

	http.HandleFunc("/", login)
	go http.ListenAndServe(":80", http.HandlerFunc(lclAddr.redirect))
	http.ListenAndServe(lclAddr.port, nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":

	}
}
