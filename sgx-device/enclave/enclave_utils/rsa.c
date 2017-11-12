#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdint.h>

#include "rsa.h"
#include "tSgxSSL_api.h"
#include "../Enclave.h"

// TODO comments and proper error cheking and return vals


RSA* t_RSA_generate_key(uint32_t keysize, uint8_t *entropy)
{
    BIGNUM *bn;
    RSA *keypair;

    RAND_seed(entropy, RSA_KEY_ENTROPY_LEN);

	bn = BN_new();
	if (bn == NULL) {
		printf("BN_new failure: %ld\n", ERR_get_error());
	    return NULL;
	}
	int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
       	printf("BN_set_word failure\n");
	    return NULL;
	}
	
	keypair = RSA_new();
	if (keypair == NULL) {
		printf("RSA_new failure: %ld\n", ERR_get_error());
	    return NULL;
	}

	ret = RSA_generate_key_ex(keypair, keysize, bn, NULL);
	if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
	    return NULL;
	}

	return keypair;
}

void t_free_rsa_key(RSA *keypair)
{
    if(keypair != NULL)
        RSA_free(keypair);
}



uint8_t* t_export_pub_key(RSA* keypair)
{

    // To get the C-string PEM form:
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, keypair);

    size_t pub_len = BIO_pending(pub);
    uint8_t *pub_key = (uint8_t*)malloc(pub_len + 1);

    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';



    return pub_key;
}

uint8_t* t_export_priv_key(RSA *keypair)
{
    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	if(ERR_get_error() != 0){
		printf("PEM_write_bio_RSAPrivateKey failure: %ld\n", ERR_get_error());
		return NULL;
	}

    size_t pri_len = BIO_pending(pri);
	if(ERR_get_error() != 0){
		printf("BIO_pending failure: %ld\n", ERR_get_error());
		return NULL;
	}

    uint8_t *pri_key = (uint8_t *)malloc(pri_len + 1);
	if(!pri_key){
		return NULL;
	}

    BIO_read(pri, pri_key, pri_len);
    pri_key[pri_len] = '\0';
	if(ERR_get_error() != 0){
		printf("BIO_read failure: %ld\n", ERR_get_error());
		return NULL;
	}

    return pri_key;
}

uint8_t* t_serialize_private_key(RSA *keypair)
{
    EVP_PKEY *evp_pkey = EVP_PKEY_new();
	if (evp_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return NULL;
	}
	EVP_PKEY_assign_RSA(evp_pkey, keypair);
	if(ERR_get_error() != 0){
		printf("EVP_PKEY_assign_RSA failure: %ld\n", ERR_get_error());
		return NULL;
	}

	uint32_t key_len = i2d_PrivateKey(evp_pkey, NULL);
	uint32_t header_len = sizeof(uint32_t);
	uint32_t header = key_len;

	uint8_t *buf = (uint8_t*) malloc(header_len + key_len);
	if(!buf){
		return NULL;
	}
	
	uint32_t *ibuf = (uint32_t *) buf;
    ibuf[0] = key_len;

	uint8_t *tbuf = buf+sizeof(uint32_t);
	i2d_PrivateKey(evp_pkey, &tbuf);
	if(ERR_get_error() != 0){
		printf("i2d_PrivateKey failure: %ld\n", ERR_get_error());
		return NULL;
	}
		


#ifdef DEBUG
	printf("der key \n");
	int32_t i;
	for (i = header_len; i < header_len + key_len; i++) {
	    printf("%02x", (uint8_t) buf[i]);
	}
	printf("\nlen: %d = %d\n", key_len, ibuf[0]);
#endif 


	return buf;
}


RSA* t_deserialize_private_key(uint8_t* buf, size_t len)
{	
	RSA *rsa;
	EVP_PKEY *evp_pkey;


	evp_pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &buf, len);
	if (ERR_get_error() != 0) {
		printf("d2i_PrivateKey failure: %ld\n", ERR_get_error());
		return NULL;
	}

	rsa = EVP_PKEY_get1_RSA(evp_pkey);
	
	EVP_PKEY_free(evp_pkey);

	return rsa;
}


int32_t t_rsa_decrypt(RSA *keypair, uint8_t *encrypted, uint8_t *decrypted)
{

    int32_t ret =  RSA_private_decrypt(RSA_KEY_SIZE/8, encrypted, decrypted, keypair, RSA_PKCS1_OAEP_PADDING);
    if(ERR_get_error()){
        printf("RSA_private_decrypt failure: %ld ret:%d\n", ERR_get_error(), ret);
        return ret;
    }

    return ret;
}
