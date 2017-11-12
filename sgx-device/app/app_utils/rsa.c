
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "rsa.h"

#define OAEP_OVERHEAD 42

RSA* rsa_import_pem_key(uint8_t *key)
{

    BIO* bio = BIO_new(BIO_s_mem());
    RSA* rsa =  RSA_new();
    if(ERR_get_error()){
        printf("BIO_new, RSA_new failure: %ld\n", ERR_get_error());
    }
    BIO_write(bio, (void*)key, strlen((const char*)key));
    if(ERR_get_error()){
        printf("BIO_write failure: %ld\n", ERR_get_error());
    }
    PEM_read_bio_RSAPublicKey(bio, &rsa, 0, 0);
    if(ERR_get_error()){
        printf("PEM_read_bio_RSA_PUBKEY failure: %ld\n", ERR_get_error());
    }
    
    BIO_free(bio);

    return rsa;
}

size_t rsa_block_size(uint8_t *key)
{
    RSA *rsa = rsa_import_pem_key(key);
    int block_size = RSA_size(rsa);

    RSA_free(rsa);
    return (size_t) block_size;
}



int rsa_encrypt(uint8_t *key, uint8_t *plaintext, size_t plen, uint8_t *ciphertext, size_t clen)
{
    uint32_t block_size, block_capacity;

    RSA *rsa = rsa_import_pem_key(key);
    RAND_seed("random seed", 10);
    
    block_size = RSA_size((RSA*)rsa);
    block_capacity = block_size - OAEP_OVERHEAD;
    
    assert(plen <= block_capacity);
    
    // int ret = RSA_public_encrypt(plen, plaintext, ciphertext, (RSA*)rsa, RSA_NO_PADDING);
    int ret = RSA_public_encrypt(plen, plaintext, ciphertext, (RSA*)rsa, RSA_PKCS1_OAEP_PADDING);
    if(ERR_get_error()){
        printf("RSA_public_encrypt failure: %ld ret:%d\n", ERR_get_error(), ret);
        return -1;
    }

    RSA_free(rsa);
    return ret;
}
