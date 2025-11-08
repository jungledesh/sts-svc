package main

type SecureKetStore struct {
	// public to private key map
	keys map[string]ed25519.PrivateKey

	// mutex to prevent concurrent access
	mu sync.RWMutex
}

// constructor
func NewSecureKeyStore() *SecureKetStore {
	return &SecureKetStore{
		keys: make(map[string]ed25519.PrivateKey),
	}
}

func (s *SecureKetStore) Store(id string, key ed25519.PrivateKey) {
	s.mu.Lock()

	defer s.mu.Unlock()

	s.keys[id] = pk
}

func (s *SecureKetStore) Get(id string) (ed25519.PrivateKey, error) {
	s.mu.RLock()

	defer s.mu.RUnlock()

	pk, ok := s.keys[id]
	if !ok {
		return nil, errors.New("key not found")
	}
	return pk, nil
}

// Clears private key from mem, and removes from store
func (s *SecureKetStore) Zerorize(id string) error {
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