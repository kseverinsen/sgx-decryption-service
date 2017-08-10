package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
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
	rth, err := c.GetRootTreeHash(context.Background(), &pb.RootTreeHashRequest{Nonce: []byte("aaaaaaaaa")})
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
	verBlock, _ := pem.Decode(pk.RSA_VerificationKey)

	encPub, err := x509.ParsePKIXPublicKey(encBlock.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	verPub, err := x509.ParsePKIXPublicKey(verBlock.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	rsaEncPub, _ := encPub.(*rsa.PublicKey)
	rsaVerPub, _ := verPub.(*rsa.PublicKey)

	// test encryption
	rng := rand.Reader

	samplePlaintext := []byte("Decrypt RPC successfull") // If this string is printed in the response, all is well.
	label := []byte("record")
	sampleCiphertext, err := rsa.EncryptOAEP(sha256.New(), rng, rsaEncPub, samplePlaintext, label)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("\nEncryption test:\nCipher: RSA OAEP with sha256, \nplaintext(hex) = %s\nlabel(hex) = %s \nciphertext(hex) = %s",
		hex.EncodeToString(samplePlaintext),
		hex.EncodeToString(label),
		hex.EncodeToString(sampleCiphertext))

	// test decryption RPC
	response, err := c.DecryptRecord(context.Background(), &pb.DecryptionRequest{Ciphertext: sampleCiphertext, ProofOfPresence: "{json proof..}", ProofOfExtension: "{json proof...}"})
	if err != nil {
		log.Fatalf("could not decrypt record: %v", err)
	} else {
		log.Printf("%s\n", response.Plaintext)
	}

	// Verify RTH
	h := sha256.Sum256(append(rth.Rth, rth.Nonce...))

	err = rsa.VerifyPKCS1v15(rsaVerPub, crypto.SHA256, h[:], rth.Sig)
	if err != nil {
		log.Fatalf("failed to verify signed root tree hash: %v", err.Error())
	}
	log.Printf("Signed RTH verified (VerifyPKCS1v15): %s", hex.EncodeToString(rth.Rth))

	// Read encrypted records from file to a hash map
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

		ct, err := base64.StdEncoding.DecodeString(line[1])

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
	fmt.Printf("\nDecrypting: %d ciphertexts from file using concurrent RPC calls\n", len(ctDB))
	var wg sync.WaitGroup

	for k, v := range ctDB {
		wg.Add(1)

		go func(sum [32]byte, ct []byte) {

			defer wg.Done()

			r, err := c.DecryptRecord(context.Background(), &pb.DecryptionRequest{Ciphertext: ct, ProofOfPresence: "{json proof..}", ProofOfExtension: "{json proof...}"})
			if err != nil {
				log.Fatalf("could not decrypt record: %v", err)
			}
			fmt.Printf("\rDecryptRecord(%s) = %d", hex.EncodeToString(sum[:]), r.Plaintext[0])
		}(k, v)

	}

	wg.Wait()
	fmt.Printf("\n")
}
