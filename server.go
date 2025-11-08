package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type APIServer struct {
	Service SignerService
}

func NewAPIServer(svc SignerService) *APIServer {
	return &APIServer{
		Service: svc,
	}
}

func (s *APIServer) Run() {
	router := http.NewServeMux()
	router.HandleFunc("POST /api/v1/keys/generate", s.handleGenKey)
	router.HandleFunc("POST /api/v1/txs/sign", s.handleTxSign)
	router.HandleFunc("GET /", s.handleRoot)

	// server w/ secure settings
	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Println("Secure Signer Service running on http://localhost:8080")
	log.Fatal(server.ListenAndServe())
}

func (s *APIServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text")
	w.Write([]byte("Hello from Secure Signer Service"))
}

func (s *APIServer) handleGenKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	acc, err := s.Service.GenerateKey(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(acc)
}

func (s *APIServer) handleTxSign(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// max body size
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	var req TransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Invalid request body: %v"}`, err), http.StatusBadRequest)
		return
	}

	// channel to get result from background go routines
	resultChan := make(chan TransactionResult)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel() // to release resources later

	// launching signing in go routine
	go func() {
		res, err := s.Service.SignTransaction(ctx, req)
		if err != nil {
			res.Error = err.Error()
		}

		select {
		case resultChan <- res:
		case <-ctx.Done():
			log.Printf("Goroutine for %s finished but context was already done.", req.KeyID)
		}
	}()

	// wait for result

	select {
	case res := <-resultChan:
		if res.Error != "" {
			http.Error(w, fmt.Sprintf(`{"error": "%s"}`, res.Error), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(res)

	case <-ctx.Done():
		http.Error(w, fmt.Sprintf(`{"error": "Tx signing request timedout"}`, http.StatusGatewayTimeout), http.StatusGatewayTimeout)
	}
}
