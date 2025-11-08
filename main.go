package main

import (
	"log"
)

func main() {

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	store := NewSecureKeyStore()
	signer := NewSignerService(store)
	server := NewAPIServer(signer)

	server.Run()
}
