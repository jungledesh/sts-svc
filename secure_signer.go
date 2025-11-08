package main

import (
	"context"        // Best practice for request-scoped data, like timeouts
	"crypto/ed25519" // For Solana-style keys
	"crypto/rand"    // For cryptographically secure randomness
	"encoding/hex"   // To create a clean string ID from the public key bytes
	"errors"
	"log"
	"sync"
)

type SecureKeyStore struct {
	// public to private key map
	keys map[string]ed25519.PrivateKey

	// mutex to prevent concurrent access
	mu sync.RWMutex
}

// constructor
func NewSecureKeyStore() *SecureKeyStore {
	return &SecureKeyStore{
		keys: make(map[string]ed25519.PrivateKey),
	}
}

func (s *SecureKeyStore) Store(id string, key ed25519.PrivateKey) {
	s.mu.Lock()

	defer s.mu.Unlock()

	s.keys[id] = pk
}

func (s *SecureKeyStore) Get(id string) (ed25519.PrivateKey, error) {
	s.mu.RLock()

	defer s.mu.RUnlock()

	pk, ok := s.keys[id]
	if !ok {
		return nil, errors.New("key not found")
	}
	return pk, nil
}

// Clears private key from mem, and removes from store
func (s *SecureKeyStore) Zerorize(id string) error {
	s.mu.Lock()

	defer s.mu.Unlock()

	pk, ok := s.keys[id]
	if !ok {
		return errors.New("Key not found")
	}

	// loop over each byte and zerorize it
	for i := range pk {
		pk[i] = 0
	}

	delete(s.key, id)

	log.Printf("Key ID %s zeroized and removed from memory store.", id)
	return nil
}

type Account struct {
	PublicKey string `json:"publickey"`
}

type TransactionRequest struct {
	KeyID          string `json:"keyId"`
	UnsignedTxData string `json:"unsignedTxData"`
}

type TransactionResult struct {
	KeyID           string `json:"keyId"`
	Signature       string `json:"signature`
	BroadcastStatus string `json:"broadcaststatus"`
	Error           string `json:"error,omitempty"`
}

type SignerService interface {
	GenerateKey(ctx context.Context) (Account, error)
	SignTransaction(ctx context.Context, req TransactionRequest) (TransactionResult, error)
}

type signerService struct {
	store *SecureKeyStore
}

func NewSignerService(store *SecureKeyStore) *signerService {
	return &signerService{
		store: store,
	}
}

func (s *signerService) GenerateKey(ctx context.Context) (Account, error) {
	log.Println("Generating new Sol Ed25519 Key Pair ... ")

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Account{}, fmt.Errorf("failed to generate key: %w", err)
	}

	// encode key
	keyId := hex.Encode(pubKey)

	s.store.Store(keyId, privKey)

	return Account{
		PublicKey: keyId,
	}, nil
}

func (s *signerService) SignTransaction(ctx context.Context, req TransactionRequest) (result TransactionResult, err error) {
	log.Printf("Attempting to sign transaction for Account: ", req.KeyID)

	defer func() {
		if r := recover(); r != nil {
			log.Printf("Critical Panic for during signing for %s, %v", req.KeyID, r)
			result.Error = "Internal Signing Error, Try again later"
			err = error.New("Signing failed due to internal error")
		}
	}()

	result.KeyID = req.KeyID

	// Input validation
	if req.KeyID == "" || req.UnsignedTxData == "" {
		return result, errors.New("KeyID and unsigned TX data cannot be empty")
	}

	rawTxData, decodeErr := base64.StdEncoding.DecodeString(req.UnsignedTxData)
	if decodeErr != nil {
		return result, fmt.Errorf("Invalid base64 encoding of tx data: %w", decodeErr)
	}

	// Key retrieval
	privKey, keyErr := s.store.Get(req.KeyID)
	if keyErr != nil {
		return result, fmt.Errorf("key retrieval failed w/ error: %w", keyErr)
	}

	sig, sigErr := ed25519.Sign(privKey, rawTxData)
	if sigErr != nil {
		return result, fmt.Errorf("cryptographic signing failed: %w", signErr)
	}

	//zerorize key
	err := s.store.Zerorize(req.keyId)
	if err != nil {
		return result, fmt.Errorf("error clearing key from mem: %w", err)
	}

	result.Signature = base64.StdEncoding.EncodeToString(sig)
	result.BroadcastStatus = "Signed and Ready"

	return result, nil

}
