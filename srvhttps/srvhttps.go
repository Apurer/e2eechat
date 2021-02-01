package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/apurer/eev"
)

type config struct {
	domain string
	port   string
}

var conf config

func (c *config) redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, fmt.Sprintf("https://%s:%s", c.domain, c.port), http.StatusMovedPermanently)
}

func init() {

	privkey := flag.String("key", "", "path to private key which is to be used for dencryption of environment variable")
	flag.Parse()

	port, err := eev.Get("HTTPS_SERVER_PORT", privkey)
	if err != nil {
		panic(err)
	}

	domain, err := eev.Get("HTTPS_SERVER_DOMAIN", privkey)
	if err != nil {
		panic(err)
	}

	conf.port = port
	conf.domain = domain
}

func main() {

	http.HandleFunc("/", login)
	go http.ListenAndServe(":80", http.HandlerFunc(conf.redirect))
	http.ListenAndServe(conf.port, nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":

	}
}
