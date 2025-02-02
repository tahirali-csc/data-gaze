package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

type Server struct {
	useTLS bool
	addr   string
}

func NewServer(useTLS bool) *Server {
	addr := ":8080"
	if useTLS {
		addr = ":8443"
	}
	return &Server{useTLS: useTLS, addr: addr}
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to SecureAPI Server!")
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handler)

	if s.useTLS {
		log.Println("Starting SecureAPI HTTPS server on", s.addr)
		server := &http.Server{
			Addr:    s.addr,
			Handler: mux,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
			log.Fatalf("HTTPS server error: %v", err)
		}
	} else {
		log.Println("Starting SecureAPI HTTP server on", s.addr)
		if err := http.ListenAndServe(s.addr, mux); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}
}
