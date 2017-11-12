# sgx-decryption-service
Client server interaction using gRPC

The remote procedure calls are defined with Protobuf in decryptionservice/decryptionservice.proto and can be compiled to Go, Java, C++ etc by using the protobuf compiler (protoc) 

* install Golang, make sure the GOROOT and GOPATH environment variables are set up correctly
* download project (stored in $GOPATH/src/github.com/sewelol/sgx-decryption-service)

      $ go get github.com/sewelol/sgx-decryption-service
      
* run server:

      $ go run server/main.go
    
* run dummy client:

      $ go run client/dummyclient.go
    

