#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include <stdlib.h>


#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>


typedef void CRYPTO_RWLOCK;

struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union {
        char *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;

void rsa_key_gen_test()
{
	BIGNUM *bn = BN_new();
	if (bn == NULL) {
		printf("BN_new failure: %ld\n", ERR_get_error());
	    return;
	}
	int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
       	printf("BN_set_word failure\n");
	    return;
	}
	
	RSA *keypair = RSA_new();
	if (keypair == NULL) {
		printf("RSA_new failure: %ld\n", ERR_get_error());
	    return;
	}
	ret = RSA_generate_key_ex(keypair, OPENSSL_RSA_FIPS_MIN_MODULUS_BITS, bn, NULL);
	if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
	    return;
	}

	EVP_PKEY *evp_pkey = EVP_PKEY_new();
	if (evp_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return;
	}
	EVP_PKEY_assign_RSA(evp_pkey, keypair);

	// public key - string
	int len = i2d_PublicKey(evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(evp_pkey, &tbuf);

	// print public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	// private key - string
	len = i2d_PrivateKey(evp_pkey, NULL);
	buf = (unsigned char *) malloc (len + 1);
	tbuf = buf;
	i2d_PrivateKey(evp_pkey, &tbuf);

	// print private key
	printf ("{\"private\":\"");
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	BN_free(bn);
	int do_rsa_free = 1;
	if (evp_pkey->pkey.rsa == keypair) {
		do_rsa_free = 0;
	}

	EVP_PKEY_free(evp_pkey);

	if (do_rsa_free) {
		RSA_free(keypair);
	}
}