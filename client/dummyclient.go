package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
	"sync"

	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	pb "github.com/sewelol/sgx-decryption-service/decryptionservice"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address     = "localhost:50051"
	defaultName = "world"
)

type leaf struct {
	Hash []byte
}

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewDecryptionDeviceClient(conn)

	//  call GetRootTreeHash
	rth, err := c.GetRootTreeHash(context.Background(), &pb.RootTreeHashRequest{Nonce: []byte("a long and random byte array")})
	if err != nil {
		log.Fatalf("could not get rth: %v", err)
	}
	log.Printf("\nRTH: %s \nNonce: %s \nSignature: %s...\n\n", hex.EncodeToString(rth.Rth), hex.EncodeToString(rth.Nonce), hex.EncodeToString(rth.Sig[:31]))

	//  call GetPublicKey
	pk, err := c.GetPublicKey(context.Background(), &pb.PublicKeyRequest{Nonce: []byte("a long and random byte array")})
	if err != nil {
		log.Fatalf("could not get quote containing the public key: %v", err)
	}
	log.Printf("Quote: %s \n encryption key: %s \n verification key: %s\n\n", pk.Quote, pk.RSA_EncryptionKey, pk.RSA_VerificationKey)

	// import public keys
	encBlock, _ := pem.Decode(pk.RSA_EncryptionKey)
	// verBlock, _ := pem.Decode(pk.RSA_VerificationKey)

	encPub, err := x509.ParsePKIXPublicKey(encBlock.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	// verPub, err := x509.ParsePKIXPublicKey(verBlock.Bytes)
	// if err != nil {
	// 	panic("failed to parse DER encoded public key: " + err.Error())
	// }

	rsaEncPub, _ := encPub.(*rsa.PublicKey)
	// rsaVerPub, _ := verPub.(*rsa.PublicKey)

	rng := rand.Reader
	label := []byte("record")

	numCrypts := 10
	log.Printf("Number of encryptions/decryptions %d", numCrypts)

	ctDB := make(map[[32]byte][]byte)

	for i := 0; i < numCrypts; i++ {
		pt := []byte{byte(i)}
		ct, _ := rsa.EncryptOAEP(sha256.New(), rng, rsaEncPub, pt, label)
		ctSum := sha256.Sum256(ct)
		ctDB[ctSum] = ct
		log.Printf("EncryptOAEP( %d )", i)
	}

	//  Remote call for DecryptRecord (concurrent)
	var wg sync.WaitGroup

	for k, v := range ctDB {
		wg.Add(1)

		go func(sum [32]byte, ct []byte) {

			defer wg.Done()

			r, err := c.DecryptRecord(context.Background(), &pb.DecryptionRequest{Ciphertext: ct, ProofOfPresence: "{json proof..}", ProofOfExtension: "{json proof...}"})
			if err != nil {
				log.Fatalf("could not decrypt record: %v", err)
			}
			log.Printf("DecryptRecord( ctDB[%s] ) = %d", hex.EncodeToString(sum[:]), r.Plaintext[0])
		}(k, v)

	}
	wg.Wait()

}
