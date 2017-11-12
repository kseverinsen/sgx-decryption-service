#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "tSgxSSL_api.h"
#include <openssl/rsa.h>
#include <openssl/sha.h>

extern "C" {
#include "enclave_utils/enclave_utils.h"
#include "enclave_utils/rsa.h"
}


// #define DEBUG


struct state_t global_state;


// printf: Invokes OCALL to display the enclave buffer to the terminal.
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

void printSHA256(uint8_t *sha256)
{
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
		printf("%02x", sha256[i]);
	} 
	printf("\n");
}

void print_global_state()
{
	uint8_t *str;

	printf("Root Tree Hash: ");
	printSHA256(global_state.root_hash);

	str = t_export_priv_key(global_state.decrypt_key);
	printf("Private crypto key:\n %s\n", str);
	free(str);

	str = t_export_pub_key(global_state.decrypt_key);
	printf("Public crypto key:\n %s\n", str);
	free(str);

	str = t_export_priv_key(global_state.signing_key);
	printf("Private signing key:\n %s\n", str);
	free(str);

	str = t_export_pub_key(global_state.signing_key);
	printf("Public signing key:\n %s\n", str);
	free(str);
}

sgx_status_t t_seal_state(uint8_t *sealed){
	sgx_status_t status = SGX_SUCCESS;


	return status;
}

sgx_status_t t_unseal_state(uint8_t *sealed){
	sgx_status_t status = SGX_SUCCESS;


	return status;
}

sgx_status_t t_initialize_enclave_state(sgx_sealed_data_t* sealed_state, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t entropy_size = RSA_KEY_ENTROPY_LEN;
	uint8_t *entropy = (uint8_t*)malloc(entropy_size); // entropy to seed the PRNG used by OpenSSL

	if(sealed_state == NULL) { // create initial state

		// Initialize the Root Tree hash sha256 context, and update it with the empty string ""
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, "", 0);
		global_state.root_hash = (uint8_t *) malloc(SHA256_DIGEST_LENGTH);
		SHA256_Final(global_state.root_hash, &sha256);
		
		// Generate the asymmetric crypto keys
		status = sgx_read_rand(entropy, entropy_size);
		if(status != SGX_SUCCESS){
			free(entropy);
			return status;
		}
		global_state.decrypt_key 	= t_RSA_generate_key(RSA_KEY_SIZE, entropy);
		
		// Generate the asymmetric signing keys
		status = sgx_read_rand(entropy, entropy_size);
		if(status != SGX_SUCCESS){
			free(entropy);
			return status;
		}
		global_state.signing_key 	= t_RSA_generate_key(RSA_KEY_SIZE, entropy);
		
		// Create a buffer containing the serialized state
		global_state.serialized_state = t_serialize_state(&global_state, SHA256_DIGEST_LENGTH);
		if(global_state.serialized_state == NULL){
			return status;
		}

	}else {
		// Unseal  blob and populate global state
		// sgx_status_t ret = sgx_unseal_data(sealed_state, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
	}

	// Export public keys to a printable PEM string
	global_state.encrypt_pem 	= (uint8_t*)t_export_pub_key(global_state.decrypt_key);
	global_state.verify_pem 	= (uint8_t*)t_export_pub_key(global_state.signing_key);


#ifdef TEST_STATE_RESTORATION
	//free global_state
	RSA_free(global_state.decrypt_key);
	RSA_free(global_state.signing_key);
	free(global_state.root_hash);
	// reinitialize global_state
	if(t_deserialize_state(global_state.serialized_state, &global_state) != 0)
		abort();
	print_global_state();
#endif

	free(entropy);
	return status;
}


sgx_status_t t_get_public_keys(	uint8_t *pem_enc_key, 
								size_t 	pem_enc_key_len,
								uint8_t *pem_verif_key, 
								size_t 	pem_verif_key_len)
{
	// UNSAFE method for getting public keys (Keys should be derlivered using an attestation report)
	// TODO: use this api call.
	// sgx_status_t sgx_create_report(const sgx_target_info_t *target_info,const sgx_report_data_t *report_data,sgx_report_t *report);
		// target_info:? quoting enclave
		// report_data: public keys
		// report: outbound buffer
	

	size_t len;

	len = strlen((const char*)global_state.encrypt_pem);

	if(pem_enc_key_len < len){
		pem_enc_key = (uint8_t*)malloc(len);
		if(pem_enc_key == NULL) return SGX_ERROR_UNEXPECTED;
	}
	memcpy(pem_enc_key, global_state.encrypt_pem, len+1);


	len	= strlen((const char*)global_state.verify_pem);

	if(pem_verif_key_len < len){
		pem_verif_key = (uint8_t*)malloc(len)+1;
		if(pem_verif_key == NULL) return SGX_ERROR_UNEXPECTED;
	}
	memcpy(pem_verif_key, global_state.verify_pem, len+1);


    return SGX_SUCCESS;
}


sgx_status_t t_decrypt_record(	uint8_t *encrypted, 
                                uint8_t *decrypted, 
                                size_t *decrypted_len)
{
	sgx_status_t status = SGX_SUCCESS;


	// Verify proofs
	uint8_t *t;
	uint8_t *p;

	// t_verify_presence(t, p);
	// t_verify_presence(tree, rth);
	// t_verify_extension(from_tree, to_tree)

	// Decrypt record in the outbound decrypted buffer
	int ret = t_rsa_decrypt(global_state.decrypt_key, encrypted, decrypted);
	if (ret < 0){
		status = SGX_ERROR_UNEXPECTED;
		//memset_s on decrypted?
	}
	else{
		*decrypted_len = ret;
	}

	// save state
	uint8_t *buf;// = malloc()
	t_seal_state(buf);
	
	// free(rth);
    return status;
}

sgx_status_t t_get_root_tree_hash(	uint8_t *nonce, 
                                    size_t nonce_len, 
                                    uint8_t *root_tree_hash, 
                                    size_t root_tree_hash_len,
                                    uint8_t *signature, 
                                    size_t signature_len)
{
    sgx_status_t status = SGX_SUCCESS;
    return status;
}



void t_test_rsa()
{
    printf("test enclave rsa operations\n");
    // rsa_key_gen_test();
    // printf("test rsa_key_gen completed\n");
	// rsa_test();
	printf("rsa_test completed\n");

	return;
}


