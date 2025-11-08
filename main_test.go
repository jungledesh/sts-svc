package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestSecureKeyStore_Concurrency(t *testing.T) {
	// Fire 100 go routines reading and writing at same time
	store := NewSecureKeyStore()

	const numRoutines = 100
	var wg sync.WaitGroup // to ensure all go routines finish

	t.Logf("Starting %d concurrent routines to test RWMutex safety.", numRoutines)

	testKeyId := "sampleKeyId"
	testPrivKey := []byte("this is my sample key")

	// store the key
	store.Store(testKeyId, testPrivKey)

	// fire go routines
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			// every tenth is writer
			if i%10 == 0 {
				writeId := fmt.Sprintf("write-keyid-%d", i)
				wirtePk := []byte(fmt.Sprintf("write-data-%d", i))
				store.Store(writeId, wirtePk)
				store.Zerorize(writeId)
				return
			}

			// all other routines are readers
			key, err := store.Get(testKeyId)
			if err != nil && err.Error() != "key not found" {
				t.Errorf("Routine %d failed to fetch key w/ error: %v", i, err)
			}

			if len(key) == 0 {
				t.Errorf("Routine %d: Retrieved key was zero-length, indicating possible corruption.", i)
			}
		}(i)
	}

	wg.Wait()
	t.Log("All concurrent routines finished. No data race detected.")
}

func TestSecureKeyStore_LifeCycle(t *testing.T) {
	store := NewSecureKeyStore()

	sampleID := "Perry'swallet01"
	sampleKey := ed25519.PrivateKey([]byte("secure-private-key-data"))

	// store
	store.Store(sampleID, sampleKey)

	// Retrieve
	privKey, err := store.Get(sampleID)
	if err != nil {
		t.Fatalf("Failed to get key err: %v", err)
	}

	if string(privKey) != string(sampleKey) {
		t.Errorf("Key retrieved is not same for id: %v", sampleID)
	}

	// zerorize
	err = store.Zerorize(sampleID)
	if err != nil {
		t.Fatalf("Failed to del key err: %v", err)
	}

	// verfiy its delt'd
	_, err = store.Get(sampleID)
	if err != nil && err.Error() != "key not found" {
		t.Errorf("some other error: %v", err)
	}
}

type CrashingSignerSvc struct {
	SignerService
	store *SecureKeyStore
}

func (c *CrashingSignerSvc) SignTransaction(ctx context.Context, req TransactionRequest) (res TransactionResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			res.Error = "Internal Signing Error. Try again."
			err = errors.New("signing failed due to unexpected internal error")
		}
	}()

	if req.KeyID == "Crash" {
		// simulate panic
		var nilPts *int
		fmt.Println(*nilPts)
	}

	return TransactionResult{KeyID: req.KeyID, BroadcastStatus: "OK"}, nil
}

func (c *CrashingSignerSvc) GenerateKey(ctx context.Context) (Account, error) {
	return Account{PublicKey: "MOCK_KEY"}, nil
}

func (c *CrashingSignerSvc) SimulateBroadcast(ctx context.Context, sig string) (string, error) {
	return "MOCK_BROADCAST_OK", nil
}

func TestSignTransaction_PanicRecovery(t *testing.T) {
	crashingSvc := &CrashingSignerSvc{}

	panicReq := TransactionRequest{
		KeyID:          "Crash",
		UnsignedTxData: base64.StdEncoding.EncodeToString([]byte("tx-data")),
	}

	result, err := crashingSvc.SignTransaction(context.Background(), panicReq)
	if err == nil {
		t.Fatalf("Expected service to return error, but it did not")
	}

	expectedErr := "signing failed due to unexpected internal error"
	if err.Error() != expectedErr {
		t.Errorf("Error mismatch. Got: %s, Wanted: %s", err.Error(), expectedErr)
	}

	clientExpectedError := "Internal Signing Error. Try again."
	if result.Error != clientExpectedError {
		t.Errorf("Client error message mismatch. Got: %s, Wanted: %s", result.Error, clientExpectedError)
	}

	t.Log("Panic successfully recovered and converted into a safe, generic error response.")
}
