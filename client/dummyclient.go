package main

import (
	"bufio"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"log"
	"os"
	"strings"
	"sync"

	"crypto/x509"
	"encoding/base64"
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
	rth, err := c.GetRootTreeHash(context.Background(), &pb.RootTreeHashRequest{Nonce: []byte("aaaaaaaaaaaaaaaaaaaaaaaa")})
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
	// encBlock, _ := pem.Decode(pk.RSA_EncryptionKey)
	verBlock, _ := pem.Decode(pk.RSA_VerificationKey)

	// encPub, err := x509.ParsePKIXPublicKey(encBlock.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	verPub, err := x509.ParsePKIXPublicKey(verBlock.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	// rsaEncPub, _ := encPub.(*rsa.PublicKey)
	rsaVerPub, _ := verPub.(*rsa.PublicKey)

	// Verify RTH
	h := sha256.Sum256(append(rth.Rth, rth.Nonce...))

	err = rsa.VerifyPKCS1v15(rsaVerPub, crypto.SHA256, h[:], rth.Sig)
	if err != nil {
		panic("failed to verify signed root tree hash: " + err.Error())
	}
	log.Printf("RTH verified: %s", hex.EncodeToString(rth.Rth))

	// Read encrypted records from file
	ctDB := make(map[[32]byte][]byte)

	file, err := os.Open("test_set/records.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// create a new scanner and read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		line := strings.Split(scanner.Text(), ",")
		// log.Println(line[1])

		ct, err := base64.StdEncoding.DecodeString(line[1])
		// ctSum, err := hex.DecodeString(line[2])

		ctSum := sha256.Sum256(ct)
		if err != nil {
			log.Fatal(err)
		}

		ctDB[ctSum] = ct
	}
	// check for errors
	if err = scanner.Err(); err != nil {
		log.Fatal(err)
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
			log.Printf("DecryptRecord(%s) = %d", hex.EncodeToString(sum[:]), r.Plaintext[0])
		}(k, v)

	}
	wg.Wait()

}
