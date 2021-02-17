package main

import (
	"os"
	"fmt"
	"net/http"

	"github.com/Apurer/eev"
	"github.com/Apurer/eev/privatekey"
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

	keypath := os.Getenv("KEYPATH")
	err := os.Unsetenv("KEYPATH")
	if err != nil {
		panic(err)
	}
	passphrase := os.Getenv("PASSPHRASE")
	err = os.Unsetenv("PASSPHRASE")
	if err != nil {
		panic(err)
	}

	privkey, err := privatekey.Read(keypath, passphrase)
	if err != nil {
		panic(err)
	}

	port, err := eev.Get("HTTPS_SERVER_PORT", privkey)
	if err != nil {
		panic(err)
	}

	domain, err := eev.Get("HTTPS_SERVER_DOMAIN", privkey)
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
