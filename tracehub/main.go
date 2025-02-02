package main

import (
	"flag"
	"fmt"
	"net/http"

	"tracehub/pkg/server"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to SecureAPI Server!")
}

func main() {
	useTLS := flag.Bool("tls", false, "Enable HTTPS mode")
	flag.Parse()

	server := server.NewServer(*useTLS)
	server.Start()
}
