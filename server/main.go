package main

import (
	"crypto/sha256"
	"log"
	"net"

	"golang.org/x/net/context"

	pb "github.com/sewelol/sgx-decryption-service/decryptionservice"
	dev "github.com/sewelol/sgx-decryption-service/device"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	port = ":50051"
)

// Decryption device
var d dev.Device

// server is used to implement helloworld.GreeterServer.
type server struct{}

func (s *server) DecryptRecord(ctx context.Context, in *pb.DecryptionRequest) (*pb.Record, error) {
	return &pb.Record{Plaintext: []byte("plaintext record")}, nil
}

func (s *server) GetRootTreeHash(ctx context.Context, in *pb.RootTreeHashRequest) (*pb.RootTreeHash, error) {

	rth, signature := d.SignRootTreeHash(in.Nonce)
	return &pb.RootTreeHash{Rth: rth, Nonce: in.Nonce, Sig: signature}, nil
}

func (s *server) GetPublicKey(ctx context.Context, in *pb.PublicKeyRequest) (*pb.Quote, error) {
	ek, vk := d.ExportPubKey()
	return &pb.Quote{Quote: "{QUOTE: {MRENCLAVE: \"enclave measurement\", MRSIGNER: \"author's identity measurement\", USERDATA: \"public keys\", SIGN: \"attestation signature\"}}", RSA_EncryptionKey: ek, RSA_VerificationKey: vk}, nil
}

func main() {
	// Initialize device
	initialRTH := sha256.Sum256([]byte(""))
	d.Init(initialRTH[:])

	// Start server
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterDecryptionDeviceServer(s, &server{})
	// Register reflection service on gRPC server.
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
