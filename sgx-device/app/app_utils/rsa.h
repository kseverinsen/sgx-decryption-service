#ifndef _UNTRUSTED_RSA_H_
#define _UNTRUSTED_RSA_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#if defined(__cplusplus)
extern "C" {
#endif

#include "rsa.c"


void* import_pem_key(uint8_t *key);
size_t rsa_block_size(uint8_t *key);
int rsa_encrypt(uint8_t *key, uint8_t *plaintext, size_t plen, uint8_t *ciphertext, size_t clen);



#if defined(__cplusplus)
}
#endif

#endif