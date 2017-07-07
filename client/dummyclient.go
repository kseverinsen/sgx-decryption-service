package main

import (
	"log"

	pb "github.com/sewelol/sgx-decryption-service/decryptionservice"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address     = "localhost:50051"
	defaultName = "world"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewDecryptionDeviceClient(conn)

	//  call DecryptRecord
	r, err := c.DecryptRecord(context.Background(), &pb.DecryptionRequest{Ciphertext: []byte("some ciphertext"), ProofOfPresence: "{json proof..}", ProofOfExtension: "{json proof...}"})
	if err != nil {
		log.Fatalf("could not decrypt record: %v", err)
	}
	log.Printf("Plaintext: %s", r.Plaintext)

	//  call GetRootTreeHash
	rth, err := c.GetRootTreeHash(context.Background(), &pb.RootTreeHashRequest{Nonce: []byte("a long and random byte array")})
	if err != nil {
		log.Fatalf("could not get rth: %v", err)
	}
	log.Printf("RTH: %s \n Nonce: %s \n Signature: %s", rth.Rth, rth.Nonce, rth.Sig)

	//  call GetPublicKey
	pk, err := c.GetPublicKey(context.Background(), &pb.PublicKeyRequest{Nonce: []byte("a long and random byte array")})
	if err != nil {
		log.Fatalf("could not get quote containing the public key: %v", err)
	}
	log.Printf("Quote: %s \n encryption key: %s \n verification key: %s", pk.Quote, pk.RSA_EncryptionKey, pk.RSA_VerificationKey)
}
