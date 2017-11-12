#ifndef RSA_H_   /* Include guard */
#define RSA_H_


#include <openssl/rsa.h>
#include <stdint.h>



RSA* t_RSA_generate_key(uint32_t keysize, uint8_t *entropy);

void t_free_rsa_key(RSA *keypair);

uint8_t* t_export_pub_key(RSA* keypair);

uint8_t* t_export_priv_key(RSA *keypair);

uint8_t* t_serialize_private_key(RSA *keypair);

RSA* t_deserialize_private_key(uint8_t* buf, size_t len);

int32_t t_rsa_decrypt(RSA *keypair, uint8_t *encrypted, uint8_t *decrypted);

#endif